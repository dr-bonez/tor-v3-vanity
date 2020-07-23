use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use sha3::{Digest, Sha3_256};

pub struct Pubkey(pub [u8; 32]);
impl AsRef<[u8; 32]> for Pubkey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
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
        data_encoding::BASE32_NOPAD.encode(&onion).to_lowercase()
    )
}

// #[accel::kernel]
pub fn try_n_from(seed: &mut [u8; 32], uc_prefix: &str, n: usize) -> bool {
    let mut cur_seed = zkp_u256::U256::from_bytes_be(&seed);
    let one: zkp_u256::U256 = 1.into();
    for _ in 0..n {
        let s = ed25519_compact::Seed::new(cur_seed.to_bytes_be());
        let kp = ed25519_compact::KeyPair::from_seed(s);

        let mut b32 = [0; 52];
        data_encoding::BASE32_NOPAD.encode_mut(&*kp.pk, &mut b32);
        if b32.starts_with(uc_prefix.as_bytes()) {
            seed.clone_from_slice(&cur_seed.to_bytes_be());
            return true;
        }

        cur_seed += one.clone();
    }
    false
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

    let prefix: &'static str = Box::leak(
        matches
            .value_of("PREFIX")
            .unwrap()
            .to_string()
            .into_boxed_str(),
    );
    let uc_prefix: &'static str = Box::leak(prefix.to_uppercase().into_boxed_str());
    let dst = matches
        .value_of("dst")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    assert!(dst.is_dir(), "dst must be a directory");
    assert!(
        prefix.chars().filter(|a| a.is_uppercase()).next().is_none(),
        "prefix must be lowercase"
    );
    data_encoding::BASE32_NOPAD
        .decode(prefix.as_bytes())
        .expect("prefix must be base32");
    let cpus = num_cpus::get();
    let (send, recv) = crossbeam_channel::unbounded();
    let (speed_send, speed_recv) = crossbeam_channel::unbounded();
    for _ in 0..cpus {
        let send = send.clone();
        let speed_send = speed_send.clone();
        std::thread::spawn(move || {
            use rand::RngCore;
            let mut seed = [0; 32];
            let mut csprng = rand::thread_rng();
            let mut now = Instant::now();
            loop {
                csprng.fill_bytes(&mut seed);
                if try_n_from(&mut seed, uc_prefix, 0x1000) {
                    send.send(seed).unwrap();
                }
                speed_send.send(now.elapsed()).unwrap();
                now = Instant::now();
            }
        });
    }
    std::thread::spawn(move || {
        let mut dur = None;
        let mut i = 0;
        let mut now = Instant::now();
        loop {
            let i_dur = speed_recv.recv().unwrap();
            dur = Some(match dur {
                Some(dur) => (dur * i + i_dur) / (i + 1),
                None => i_dur,
            });
            i += 1;
            if now.elapsed() > Duration::from_secs(60) {
                now = Instant::now();
                i = 0;
                let est = dur.unwrap() * 1073741824 / cpus as u32;
                println!("Estimated {}", durationfmt::to_string(est));
            }
        }
    });
    loop {
        use std::io::Write;

        let seed = recv.recv().unwrap();
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
        let onion = pubkey_to_onion(&*kp.pk);
        println!("{}", onion);
        let mut f = std::fs::File::create(onion).unwrap();
        f.write_all(FILE_PREFIX).unwrap();
        f.write_all(&*kp.sk).unwrap();
        f.flush().unwrap();
    }
}
