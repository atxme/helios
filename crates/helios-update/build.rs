fn main() {
    let target = std::env::var("TARGET").expect("Cargo fournit TARGET au build script");
    println!("cargo:rustc-env=HELIOS_BUILD_TARGET={target}");
}
