use ptx_builder::error::Result;
use ptx_builder::prelude::*;

fn main() -> Result<()> {
    // Workaround for "crate required to be available in rlib format" bug
    std::env::set_var("CARGO_BUILD_PIPELINING", "false");

    // Help cargo find libcuda
    println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64/");


    let builder = Builder::new("core")?;
    CargoAdapter::with_env_var("KERNEL_PTX_PATH").build(builder);
}