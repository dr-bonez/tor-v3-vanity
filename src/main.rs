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

pub struct PrettyRate(f64);
impl std::fmt::Display for PrettyRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 >= 1e9 {
            write!(f, "{:.3} Gkeys/s", self.0 / 1e9)
        } else if self.0 >= 1e6 {
            write!(f, "{:.3} Mkeys/s", self.0 / 1e6)
        } else if self.0 >= 1e3 {
            write!(f, "{:.3} Kkeys/s", self.0 / 1e3)
        } else {
            write!(f, "{:.0} keys/s", self.0)
        }
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

/// Longest prefix that lies entirely within the public key (the rest of the address is the
/// checksum and version).
const MAX_PREFIX_LEN: usize = 51;

pub fn prefix_from_str(s: &str) -> core::Prefix {
    assert!(
        s.len() <= MAX_PREFIX_LEN,
        "prefix must be at most {} characters",
        MAX_PREFIX_LEN
    );
    let bytes = base32::decode(
        base32::Alphabet::RFC4648 { padding: false },
        &format!("{:a<56}", s),
    )
    .expect("prefix must be base32");
    let mut value = [0u32; 8];
    let mut mask = [0u32; 8];
    for bit in 0..5 * s.len() {
        // base32 is big-endian within each byte, the words are little-endian
        let (byte, shift) = (bit / 8, 7 - bit % 8);
        mask[byte / 4] |= 1 << (8 * (byte % 4) + shift);
        value[byte / 4] |= ((bytes[byte] >> shift) as u32 & 1) << (8 * (byte % 4) + shift);
    }
    // The top bit is the sign of x, which the GPU doesn't compute. The host checks it.
    mask[7] &= 0x7fff_ffff;
    value[7] &= 0x7fff_ffff;
    core::Prefix { value, mask }
}

fn assert_crypto_rng<Rng: rand::CryptoRng>(rng: Rng) -> Rng {
    rng
}

/// Max matches reported per launch; more are dropped (only relevant for very short prefixes).
const FOUND_CAP: usize = 1024;

pub fn cuda_try_loop(
    prefixes: &[String],
    sender: crossbeam_channel::Sender<[u8; 32]>,
    tries_sender: crossbeam_channel::Sender<u64>,
) -> Result<(), Error> {
    use tor_v3_vanity_core::ed25519::GeP3;
    use rustacuda::launch;
    use rustacuda::memory::DeviceBox;
    use rustacuda::prelude::*;
    use std::ffi::CString;

    let mut eight = [0; 32];
    eight[0] = 8;
    let step = GeP3::base().scalarmult(&eight).to_precomp();
    let gpu_prefixes: Vec<_> = prefixes.iter().map(|p| prefix_from_str(p)).collect();

    // Create a context associated to this device
    // TODO: keep alive
    rustacuda::init(CudaFlags::empty())?;
    let mut i = 0;
    for device in rustacuda::device::Device::devices()? {
        let device = device?;
        let gpu_prefixes = gpu_prefixes.clone();
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
            let render = kernel
                .get_function(std::ffi::CStr::from_bytes_with_nul(b"render\0").unwrap())
                .unwrap();

            // Create a stream to submit work to
            let stream = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();

            // calculate threads and blocks to fill every SM once
            use rustacuda::device::DeviceAttribute as DA;
            let attr = |a| device.get_attribute(a).unwrap() as u32;
            let fn_max_threads = render
                .get_attribute(rustacuda::function::FunctionAttribute::MaxThreadsPerBlock)
                .unwrap() as u32;
            let fn_registers = render
                .get_attribute(rustacuda::function::FunctionAttribute::NumRegisters)
                .unwrap() as u32;
            let threads = std::cmp::min(256, fn_max_threads);
            let blocks_per_sm = std::cmp::max(
                1,
                std::cmp::min(
                    attr(DA::MaxThreadsPerMultiprocessor) / threads,
                    attr(DA::MaxRegistersPerMultiprocessor) / (fn_registers * threads),
                ),
            );
            let blocks = attr(DA::MultiprocessorCount) * blocks_per_sm;
            let total_threads = (blocks * threads) as usize;

            // A random clamped scalar. Bit 253 is cleared so adding thread and step offsets
            // can never carry into bit 254.
            let mut base_scalar = [0; 32];
            csprng.fill_bytes(&mut base_scalar);
            base_scalar[0] &= 248;
            base_scalar[31] = (base_scalar[31] & 31) | 64;

            let mut points = unsafe { DeviceBuffer::uninitialized(total_threads) }.unwrap();
            let mut gpu_prefix_buf = DeviceBuffer::from_slice(&gpu_prefixes).unwrap();
            let mut found_count = DeviceBox::new(&0u32).unwrap();
            let mut found = unsafe { DeviceBuffer::uninitialized(FOUND_CAP) }.unwrap();
            let mut params = DeviceBox::new(&core::KernelParams {
                base_scalar,
                step,
                points: points.as_device_ptr(),
                prefixes: gpu_prefix_buf.as_device_ptr(),
                prefixes_len: gpu_prefix_buf.len(),
                found_count: found_count.as_device_ptr(),
                found: found.as_device_ptr(),
                found_cap: FOUND_CAP as u32,
            })
            .unwrap();

            println!(
                "Launching kernel on device #{} with {} threads and {} blocks ({} registers)",
                i, threads, blocks, fn_registers
            );
            unsafe {
                launch!(kernel.init<<<blocks, threads, 0, stream>>>(params.as_device_ptr()))
                    .unwrap();
            }
            stream.synchronize().unwrap();

            let mut found_host = vec![core::Found { thread: 0, iter: 0 }; FOUND_CAP];
            for launch in 0u64.. {
                unsafe {
                    launch!(kernel.render<<<blocks, threads, 0, stream>>>(params.as_device_ptr()))
                        .unwrap();
                }

                // The kernel launch is asynchronous, so we wait for the kernel to finish executing
                stream.synchronize().unwrap();

                let mut count = 0u32;
                found_count.copy_to(&mut count).unwrap();
                if count > 0 {
                    found_count.copy_from(&0).unwrap();
                    found.copy_to(&mut found_host[..]).unwrap();
                    for f in &found_host[..std::cmp::min(count as usize, FOUND_CAP)] {
                        let step = launch * core::KEYS_PER_LAUNCH as u64 + f.iter as u64;
                        sender
                            .send(core::thread_scalar(&base_scalar, f.thread as u64, step))
                            .unwrap();
                    }
                }

                tries_sender
                    .send(total_threads as u64 * core::KEYS_PER_LAUNCH as u64)
                    .unwrap();
            }
        });
        i += 1;
    }
    if i == 0 {
        eprintln!("No cuda devices available.");
        std::process::exit(2);
    }
    Ok(())
}

const FILE_PREFIX: &'static [u8] = b"== ed25519v1-secret: type0 ==\0\0\0";

fn main() {
    let app = clap::App::new("t3v")
        .arg(
            clap::Arg::with_name("PREFIX")
                .required_unless("bench")
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
        )
        .arg(
            clap::Arg::with_name("bench")
                .long("bench")
                .takes_value(true)
                .value_name("SECONDS")
                .help("Measure the key generation rate for SECONDS and exit"),
        );
    let matches = app.get_matches();

    let bench = matches.value_of("bench").map(|s| {
        s.parse::<f64>()
            .expect("bench must be a number of seconds")
    });
    let prefixes: Vec<_> = match matches.values_of("PREFIX") {
        Some(values) => values.map(|a| a.to_lowercase()).collect(),
        // 80 bits that will never match, so the benchmark measures pure throughput
        None => vec!["a".repeat(16)],
    };
    let max_len = prefixes
        .iter()
        .fold(0, |acc, x| std::cmp::max(acc, x.len()));
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
        let expected = 2_f64.powi(5 * max_len as i32);
        // The first batch includes kernel warm-up, so rates are measured from its completion
        let mut tries = recv_tries.recv().unwrap() as f64;
        let rate_start = Instant::now();
        let rate_start_tries = tries;
        let mut last_log = Instant::now();
        let mut last_log_tries = tries;
        loop {
            tries += recv_tries.recv().unwrap() as f64;
            if let Some(secs) = bench {
                let elapsed = rate_start.elapsed().as_secs_f64();
                if elapsed >= secs {
                    let measured = tries - rate_start_tries;
                    let rate = measured / elapsed;
                    println!(
                        "Benchmark: {:.0} keys in {:.2}s = {} ({:.0} keys/s)",
                        measured,
                        elapsed,
                        PrettyRate(rate),
                        rate
                    );
                    std::process::exit(0);
                }
                continue;
            }
            let dur = now.elapsed().as_secs_f64();
            let dur_pretty =
                PrettyDur(chrono::Duration::from_std(Duration::from_secs_f64(dur)).unwrap());
            let progress = tries / expected;
            let expected_dur = dur / progress;
            let expected_dur_pretty = PrettyDur(
                chrono::Duration::from_std(Duration::from_secs_f64(expected_dur)).unwrap(),
            );
            if last_log.elapsed() > Duration::from_secs(30) {
                println!("Tried {:.0} / {:.0} (expected) keys.", tries, expected);
                println!(
                    "Running for {} / {} (expected).",
                    dur_pretty, expected_dur_pretty
                );
                let window = last_log.elapsed().as_secs_f64();
                println!(
                    "Rate: {} (last {:.0}s), {} (average).",
                    PrettyRate((tries - last_log_tries) / window),
                    window,
                    PrettyRate((tries - rate_start_tries) / rate_start.elapsed().as_secs_f64())
                );
                last_log = Instant::now();
                last_log_tries = tries;
            }
        }
    });

    loop {
        use std::io::Write;

        use rand::RngCore;

        // The GPU searches secret scalars directly, so the key is stored in expanded form:
        // the scalar followed by a random nonce half.
        let scalar = recv.recv().unwrap();
        let mut expanded = [0; 64];
        expanded[..32].copy_from_slice(&scalar);
        rand::thread_rng().fill_bytes(&mut expanded[32..]);
        let esk = ed25519_dalek::ExpandedSecretKey::from_bytes(&expanded).unwrap();
        let pk: ed25519_dalek::PublicKey = (&esk).into();
        let onion = pubkey_to_onion(pk.as_bytes());
        // The GPU ignores the sign bit, so a full-length prefix can produce false positives
        if !prefixes.iter().any(|p| onion.starts_with(p.as_str())) {
            eprintln!("Discarding false positive {}", onion);
            continue;
        }
        println!("{}", onion);
        let mut f = std::fs::File::create(dst.join(onion)).unwrap();
        f.write_all(FILE_PREFIX).unwrap();
        f.write_all(&esk.to_bytes()).unwrap();
        f.flush().unwrap();
    }
}
