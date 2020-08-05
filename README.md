# tor-v3-vanity
A TOR v3 vanity url generator designed to run on an NVIDIA GPU.

Disclaimer: This project is brand new and hasn't been thoroughly vetted.
Please report any bugs you find [here](https://github.com/dr-bonez/tor-v3-vanity/issues).

The program is designed to use all available cuda devices, and will automatically decide the number of threads and blocks to use.

## Installation

- [Install Rust](https://rustup.rs)
- [Install Cuda](https://developer.nvidia.com/cuda-downloads)
- `rustup target add nvptx64-nvidia-cuda`
- `cargo install ptx-linker`
- `git clone https://github.com/dr-bonez/tor-v3-vanity`
- `cd tor-v3-vanity`
- `cargo install --path .`

## Usage

- Create output dir
  - `mkdir mykeys`
- Run `t3v`
  - `t3v --dst mykeys/ myprefix`
- Use the resulting file as your `hs_ed25519_secret_key`
  - `cat mykeys/myprefixwhatever.onion > /var/lib/tor/hidden_service/hs_ed25519_secret_key`

## Bench
On my 1070ti, I get the following time estimates:

| Prefix Length | Time      |
| ------------- | --------- |
|             5 | 7 minutes |
|             6 | 3.5 hours |
|             7 | 5.5 days  |
|             8 | 23 weeks  |
