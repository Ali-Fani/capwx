//! Build the vendored HashWX C sources into one shared library.
//!
//! `HASHWX_SRC` must point at the `third_party/hashwx` checkout (the LGPL source snapshot that
//! capwx already ships in the sdist). Nothing is copied: the library is built from that tree.

fn main() {
    let src = std::env::var("HASHWX_SRC")
        .expect("set HASHWX_SRC to the third_party/hashwx directory");
    let mut build = cc::Build::new();
    build
        .include(format!("{src}/include"))
        .include(format!("{src}/src"))
        .define("HASHWX_STATIC", None)
        .warnings(false)
        .opt_level(3);
    for file in [
        "compiler.c",
        "compiler_a64.c",
        "compiler_x86.c",
        "context.c",
        "hashwx.c",
        "program.c",
        "program_exec.c",
        "siphash_rng.c",
        "virtual_memory.c",
    ] {
        build.file(format!("{src}/src/{file}"));
    }
    build.compile("hashwx");
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-env-changed=HASHWX_SRC");
}
