use cc;
use std::env;
fn main() {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let profile = env::var("PROFILE").unwrap();
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    let includes = vec![
        format!("{}/include", sdk_dir),
        "./codegen".to_string(),
        "../include".to_string(),
        "/root/sgx-rust/edl".to_string(),
    ];

    let mut base_u = cc::Build::new()
        .file("./codegen/Enclave_u.c")
        .no_default_flags(true)
        .includes(includes)
        .flag("-fstack-protector")
        .flag("-fPIC")
        .flag("-Wno-attributes")
        .flag("-m64")
        .flag("-ggdb")
        .shared_flag(true)
        .to_owned();

    if (profile == "release") {
        base_u.flag("-O2").compile("Enclave_u");
    } else {
        base_u.flag("-O0").flag("-g").compile("Enclave_u");
    }

    // NOTE: This is for the integration tests. Currently this only works if the
    // nightly toolchain is installed, and if you test running
    // `cargo +nightly test -Z extra-link-arg`
    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-arg=-lsgx_uprotected_fs");

    println!("cargo:rustc-link-arg=-lsgx_dcap_ql");

    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-cfg=sgx_mode=\"SW\"");
            println!("cargo:rustc-link-arg=-lsgx_urts_sim");
            println!("cargo:rustc-link-arg=-lsgx_uae_service_sim");
        }
        _ => {
            // HW by default
            println!("cargo:rustc-cfg=sgx_mode=\"HW\"");
            println!("cargo:rustc-link-arg=-lsgx_urts");
            println!("cargo:rustc-link-arg=-lsgx_uae_service");
        }
    }
}
