use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use failure::Error;
use sha3::{Digest, Sha3_256};
use tor_v3_vanity_core as core;

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

pub struct BytePrefixOwned {
    pub byte_prefix: rustacuda::memory::DeviceBuffer<u8>,
    pub last_byte_idx: usize,
    pub last_byte_mask: u8,
    pub out: rustacuda::memory::DeviceBuffer<u8>,
    pub success: rustacuda::memory::DeviceBox<bool>,
}
impl BytePrefixOwned {
    pub fn from_str(s: &str) -> Self {
        let byte_prefix = base32::decode(
            base32::Alphabet::RFC4648 { padding: false },
            &format!("{}aa", s),
        )
        .expect("prefix must be base32");
        let mut last_byte_idx = 5 * s.len() / 8 - 1;
        let n_bits = (5 * s.len()) % 8;
        let last_byte_mask = ((1 << n_bits) - 1) << (8 - n_bits);
        if last_byte_mask > 0 {
            last_byte_idx += 1;
        }
        let gpu_byte_prefix = rustacuda::memory::DeviceBuffer::from_slice(&byte_prefix).unwrap();
        let out = [0; 32];
        let gpu_out = rustacuda::memory::DeviceBuffer::from_slice(&out).unwrap();
        let success = false;
        let gpu_success = rustacuda::memory::DeviceBox::new(&success).unwrap();
        BytePrefixOwned {
            byte_prefix: gpu_byte_prefix,
            last_byte_idx,
            last_byte_mask,
            out: gpu_out,
            success: gpu_success,
        }
    }
    pub fn as_byte_prefix(&mut self) -> core::BytePrefix {
        core::BytePrefix {
            byte_prefix: self.byte_prefix.as_device_ptr(),
            byte_prefix_len: self.byte_prefix.len(),
            last_byte_idx: self.last_byte_idx,
            last_byte_mask: self.last_byte_mask,
            out: self.out.as_device_ptr(),
            success: self.success.as_device_ptr(),
        }
    }
}

fn assert_crypto_rng<Rng: rand::CryptoRng>(rng: Rng) -> Rng {
    rng
}

pub fn cuda_try_loop(
    prefixes: &[String],
    sender: crossbeam_channel::Sender<[u8; 32]>,
    tries_sender: crossbeam_channel::Sender<u64>,
) -> Result<(), Error> {
    use rustacuda::launch;
    use rustacuda::memory::DeviceBox;
    use rustacuda::prelude::*;
    use std::ffi::CString;

    // Create a context associated to this device
    // TODO: keep alive
    rustacuda::init(CudaFlags::empty())?;
    for device in rustacuda::device::Device::devices()? {
        let device = device?;
        let prefixes = prefixes.to_owned();
        let sender = sender.clone();
        let tries_sender = tries_sender.clone();
        std::thread::spawn(move || {
            use rand::RngCore;
            let mut csprng = assert_crypto_rng(rand::thread_rng());
            let _context =
                Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device)
                    .unwrap();

            // Load PTX module
            let module_data = CString::new(include_str!(env!("KERNEL_PTX_PATH"))).unwrap();
            let kernel = Module::load_from_string(&module_data).unwrap();

            // Create a stream to submit work to
            let stream = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();

            // Move seed and prefix to device
            let mut seed = [0; 32];
            let mut gpu_seed = DeviceBuffer::from_slice(&seed).unwrap();

            let mut byte_prefixes_owned: Vec<_> = prefixes
                .into_iter()
                .map(|a| BytePrefixOwned::from_str(&a))
                .collect();
            let mut byte_prefixes: Vec<_> = byte_prefixes_owned
                .iter_mut()
                .map(|bp| bp.as_byte_prefix())
                .collect();
            let mut gpu_byte_prefixes = DeviceBuffer::from_slice(&byte_prefixes).unwrap();

            // Crate parameters
            let mut params = DeviceBox::new(&core::KernelParams {
                seed: gpu_seed.as_device_ptr(),
                byte_prefixes: gpu_byte_prefixes.as_device_ptr(),
                byte_prefixes_len: gpu_byte_prefixes.len(),
            })
            .unwrap();

            // Do rendering
            let threads = device
                .get_attribute(rustacuda::device::DeviceAttribute::MaxThreadsPerBlock)
                .unwrap() as u32;
            let blocks = device
                .get_attribute(rustacuda::device::DeviceAttribute::MultiprocessorCount)
                .unwrap() as u32;

            loop {
                csprng.fill_bytes(&mut seed);
                gpu_seed.copy_from(&seed).unwrap();
                unsafe {
                    launch!(kernel.render<<<blocks, threads, 0, stream>>>(params.as_device_ptr()))
                        .unwrap();
                }

                // The kernel launch is asynchronous, so we wait for the kernel to finish executing
                stream.synchronize().unwrap();

                gpu_byte_prefixes.copy_to(&mut byte_prefixes).unwrap();

                for prefix in &mut byte_prefixes_owned {
                    let mut success = false;
                    prefix.success.copy_to(&mut success).unwrap();
                    if success {
                        prefix.success.copy_from(&false).unwrap();
                        let mut out = [0; 32];
                        prefix.out.copy_to(&mut out).unwrap();
                        sender.send(out).unwrap();
                    }
                }

                tries_sender.send(threads as u64 * blocks as u64).unwrap();
            }
        });
    }
    Ok(())
}

const FILE_PREFIX: &'static [u8] = b"== ed25519v1-secret: type0 ==\0\0\0";

fn main() {
    let app = clap::App::new("t3v")
        .arg(
            clap::Arg::with_name("PREFIX")
                .required(true)
                .multiple(true)
                .value_delimiter(",")
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

    let max_len = matches
        .values_of("PREFIX")
        .unwrap()
        .fold(0, |acc, x| std::cmp::max(acc, x.len()));
    let prefixes: Vec<_> = matches
        .values_of("PREFIX")
        .unwrap()
        .map(|a| a.to_string())
        .collect();
    let dst = matches
        .value_of("dst")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    assert!(dst.is_dir(), "dst must be a directory");

    let (send, recv) = crossbeam_channel::unbounded();
    let (send_tries, recv_tries) = crossbeam_channel::bounded(1);
    cuda_try_loop(&prefixes, send, send_tries).unwrap();

    std::thread::spawn(move || {
        let now = Instant::now();
        let mut tries = 0_f64;
        let expected = 2_f64.powi(5 * max_len as i32);
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
        let esk: ed25519_dalek::ExpandedSecretKey =
            (&ed25519_dalek::SecretKey::from_bytes(&seed).unwrap()).into();
        let pk: ed25519_dalek::PublicKey = (&esk).into();
        let onion = pubkey_to_onion(pk.as_bytes());
        println!("{}", onion);
        let mut f = std::fs::File::create(dst.join(onion)).unwrap();
        f.write_all(FILE_PREFIX).unwrap();
        f.write_all(&esk.to_bytes()).unwrap();
        f.flush().unwrap();
    }
}
