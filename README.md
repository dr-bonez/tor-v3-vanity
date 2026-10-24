# tor-v3-vanity
A TOR v3 vanity url generator designed to run on an NVIDIA GPU.

Disclaimer: This project is brand new and hasn't been thoroughly vetted.
Please report any bugs you find [here](https://github.com/dr-bonez/tor-v3-vanity/issues).

The program is designed to use all available cuda devices, and will automatically decide the number of threads and blocks to use.

Now supports multiple prefixes!

## Installation

- [Install Rust](https://rustup.rs)
- [Install Cuda](https://developer.nvidia.com/cuda-downloads)
- `rustup install nightly`
- `rustup target add nvptx64-nvidia-cuda`
- `cargo install ptx-linker`
- `git clone https://github.com/dr-bonez/tor-v3-vanity`
- `cd tor-v3-vanity`
- `cargo +nightly install --path .`

## Usage

- Create output dir
  - `mkdir mykeys`
- Run `t3v`
  - `t3v --dst mykeys/ myprefix1,myprefix2`
- Use the resulting file as your `hs_ed25519_secret_key`
  - `cat mykeys/myprefixwhatever.onion > /var/lib/tor/hidden_service/hs_ed25519_secret_key`

## Bench
Measure your GPU with `t3v --bench 15`. An RTX 5090 checks about 3.97 Gkeys/s, which gives
the following expected times per match:

| Prefix Length | Time        |
| ------------- | ----------- |
|             7 | 9 seconds   |
|             8 | 4.6 minutes |
|             9 | 2.5 hours   |
|            10 | 3.3 days    |
|            11 | 15 weeks    |
|            12 | 9.2 years   |
