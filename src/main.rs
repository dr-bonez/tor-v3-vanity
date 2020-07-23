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
    let mut onion = Vec::with_capacity(35);
    onion.extend_from_slice(pubkey);
    onion.extend_from_slice(&hasher.finalize()[..2]);
    onion.push(3);
    format!(
        "{}.onion",
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &onion).to_lowercase()
    )
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
    let dst = matches
        .value_of("dst")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    assert!(dst.is_dir(), "dst must be a directory");
    assert!(
        prefix.chars().filter(|a| a.is_uppercase()).next().is_none(),
        "prefix must be lowercase"
    );
    assert!(
        base32::decode(base32::Alphabet::RFC4648 { padding: false }, prefix).is_some(),
        "prefix must be base32"
    );
    let cpus = num_cpus::get();
    let (send, recv) = crossbeam_channel::unbounded();
    let (speed_send, speed_recv) = crossbeam_channel::unbounded();
    for _ in 0..cpus {
        let send = send.clone();
        let speed_send = speed_send.clone();
        std::thread::spawn(move || {
            let mut csprng = rand::thread_rng();
            let mut now = Instant::now();
            let mut i: usize = 0;
            loop {
                let kp = ed25519_dalek::Keypair::generate(&mut csprng);
                let onion = pubkey_to_onion(&kp.public.as_bytes());
                if onion.starts_with(prefix) {
                    send.send((onion, kp)).unwrap();
                }
                i += 1;
                if i >= 32768 {
                    speed_send.send(now.elapsed()).unwrap();
                    now = Instant::now();
                    i = 0;
                }
            }
        });
    } //c
    std::thread::spawn(move || {
        let mut dur = None;
        let mut i = 0;
        let mut now = Instant::now();
        loop {
            let i_dur = speed_recv.recv().unwrap();
            dur = Some(match dur {
                Some(dur) => (dur * i + i_dur) / (1 + i),
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

        let (onion, kp) = recv.recv().unwrap();
        println!("{}", onion);
        let mut f = std::fs::File::create(onion).unwrap();
        f.write_all(FILE_PREFIX).unwrap();
        f.write_all(kp.secret.as_bytes()).unwrap();
        f.flush().unwrap();
    }
}
