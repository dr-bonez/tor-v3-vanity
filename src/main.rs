use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use failure::Error;
use sha3::{Digest, Sha3_256};
use tor_v3_vanity_core as core;

const GPU_THREADS: u64 = 256;
const GPU_BLOCKS: u64 = 4096;

pub struct Pubkey(pub [u8; 32]);
impl AsRef<[u8; 32]> for Pubkey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct PrettyDur(chrono::Duration);
impl std::fmt::Display for PrettyDur {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.num_weeks() >= 52 {
            write!(f, "{} years, ", self.0.num_weeks() / 52)?;
        }
        if self.0.num_weeks() % 52 > 0 {
            write!(f, "{} weeks, ", self.0.num_weeks() % 52)?;
        }
        if self.0.num_days() % 7 > 0 {
            write!(f, "{} days, ", self.0.num_days() % 7)?;
        }
        if self.0.num_hours() % 24 > 0 {
            write!(f, "{} hours, ", self.0.num_hours() % 24)?;
        }
        if self.0.num_minutes() % 60 > 0 {
            write!(f, "{} minutes, ", self.0.num_minutes() % 60)?;
        }
        write!(f, "{} seconds", self.0.num_seconds() % 60)
    }
}

pub fn pubkey_to_onion(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update(&[3]);
    let mut onion = [0; 35];
    onion[..32].clone_from_slice(pubkey);
    onion[32..34].clone_from_slice(&hasher.finalize()[..2]);
    onion[34] = 3;
    format!(
        "{}.onion",
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &onion).to_lowercase()
    )
}

pub fn cuda_try(seed: &[u8; 32], byte_prefix: &[u8], last_byte_idx: usize, last_byte_mask: u8) -> Result<Option<[u8; 32]>, Error> {
    use rustacuda::launch;
    use rustacuda::memory::DeviceBox;
    use rustacuda::prelude::*;
    use std::ffi::CString;

    // Create a context associated to this device
    // TODO: keep alive
    rustacuda::init(CudaFlags::empty())?;
    let device = Device::get_device(0)?;
    let _context =
        Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device)?;

    // Load PTX module
    let module_data = CString::new(include_str!(env!("KERNEL_PTX_PATH")))?;
    let kernel = Module::load_from_string(&module_data)?;

    // Create a stream to submit work to
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

    // Move seed and prefix to device
    let mut gpu_seed = DeviceBuffer::from_slice(seed)?;
    let mut gpu_uc_prefix = DeviceBuffer::from_slice(byte_prefix)?;

    // Create output
    let mut out = [0; 32];
    let mut gpu_out = DeviceBuffer::from_slice(&out)?;

    let mut success = false;
    let mut gpu_success = DeviceBox::new(&success)?;

    // Crate parameters
    let mut params = DeviceBox::new(&core::KernelParams {
        seed: gpu_seed.as_device_ptr(),
        byte_prefix: gpu_uc_prefix.as_device_ptr(),
        byte_prefix_len: gpu_uc_prefix.len(),
        last_byte_idx: last_byte_idx,
        last_byte_mask: last_byte_mask,
        out: gpu_out.as_device_ptr(),
        success: gpu_success.as_device_ptr(),
    })?;

    // Do rendering
    let threads = GPU_THREADS as u32;
    let blocks = GPU_BLOCKS as u32;

    unsafe {
        launch!(kernel.render<<<blocks, threads, 0, stream>>>(params.as_device_ptr()))?;
    }

    // The kernel launch is asynchronous, so we wait for the kernel to finish executing
    stream.synchronize()?;

    // Copy the result back to the host
    gpu_success.copy_to(&mut success)?;
    if success {
        gpu_out.copy_to(&mut out)?;
        Ok(Some(out))
    } else {
        Ok(None)
    }
}

const FILE_PREFIX: &'static [u8] = b"== ed25519v1-secret: type0 ==\0\0\0";

fn main() {
    let app = clap::App::new("t3v")
        .arg(
            clap::Arg::with_name("PREFIX")
                .required(true)
                .help("Desired prefix"),
        )
        .arg(
            clap::Arg::with_name("dst")
                .long("dst")
                .short("d")
                .takes_value(true)
                .help("Destination folder"),
        );
    let matches = app.get_matches();

    let prefix = matches
        .value_of("PREFIX")
        .unwrap()
        .to_string()
        .into_boxed_str();
    let dst = matches
        .value_of("dst")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    assert!(dst.is_dir(), "dst must be a directory");
    let byte_prefix: &'static [u8] = Box::leak(
        base32::decode(
            base32::Alphabet::RFC4648 { padding: false },
            &format!("{}aa", prefix),
        )
        .expect("prefix must be base32")
        .into_boxed_slice(),
    );
    let mut last_byte_idx = 5 * prefix.len() / 8 - 1;
    let n_bits = (5 * prefix.len()) % 8;
    let last_byte_mask = ((1 << n_bits) - 1) << (8 - n_bits);
    if last_byte_mask > 0 {
        last_byte_idx += 1;
    }

    let (send, recv) = crossbeam_channel::unbounded();
    let (send_tries, recv_tries) = crossbeam_channel::bounded(1);
    std::thread::spawn(move || {
        use rand::RngCore;
        let mut seed = [0; 32];
        let mut csprng = rand::thread_rng();
        loop {
            csprng.fill_bytes(&mut seed);
            let res = cuda_try(&seed, byte_prefix, last_byte_idx, last_byte_mask).unwrap();
            if let Some(seed) = res {
                send.send(seed).unwrap();
            } else {
                send_tries.send(GPU_BLOCKS * GPU_THREADS).unwrap();
            }
        }
    });

    std::thread::spawn(move || {
        let now = Instant::now();
        let mut tries = 0_f64;
        let expected = 2_f64.powi(5 * prefix.len() as i32);
        loop {
            tries += recv_tries.recv().unwrap() as f64;
            let dur = now.elapsed().as_secs_f64();
            let dur_pretty =
                PrettyDur(chrono::Duration::from_std(Duration::from_secs_f64(dur)).unwrap());
            let progress = tries / expected;
            let expected_dur = dur / progress;
            let expected_dur_pretty = PrettyDur(
                chrono::Duration::from_std(Duration::from_secs_f64(expected_dur)).unwrap(),
            );
            println!("Tried {:.0} / {:.0} (expected) keys.", tries, expected);
            println!(
                "Running for {} / {} (expected).",
                dur_pretty, expected_dur_pretty
            );
        }
    });

    loop {
        use std::io::Write;

        let seed = recv.recv().unwrap();
        let esk: ed25519_dalek::ExpandedSecretKey = (&ed25519_dalek::SecretKey::from_bytes(&seed).unwrap()).into();
        let pk: ed25519_dalek::PublicKey = (&esk).into();
        let onion = pubkey_to_onion(pk.as_bytes());
        println!("{}", onion);
        let mut f = std::fs::File::create(dst.join(onion)).unwrap();
        f.write_all(FILE_PREFIX).unwrap();
        f.write_all(&esk.to_bytes()).unwrap();
        f.flush().unwrap();
    }
}
