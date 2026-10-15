use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn field(value: &Value) -> [u8; 32] {
    let decimal = value.as_str().expect("coordinate must be a decimal string");
    let bytes = BigUint::parse_bytes(decimal.as_bytes(), 10)
        .expect("invalid decimal coordinate")
        .to_bytes_be();
    assert!(bytes.len() <= 32, "coordinate exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn g1(point: &Value) -> Vec<u8> {
    let coords = point.as_array().expect("G1 point must be an array");
    assert!(coords.len() >= 2);
    [field(&coords[0]).as_slice(), field(&coords[1]).as_slice()].concat()
}

fn g2(point: &Value) -> Vec<u8> {
    let coords = point.as_array().expect("G2 point must be an array");
    assert!(coords.len() >= 2);
    let x = coords[0].as_array().expect("G2 x must be an array");
    let y = coords[1].as_array().expect("G2 y must be an array");
    assert!(x.len() >= 2 && y.len() >= 2);
    // Solana alt_bn128 encodes Fp2 as c1 || c0, each component big endian.
    [field(&x[1]).as_slice(), field(&x[0]).as_slice(),
     field(&y[1]).as_slice(), field(&y[0]).as_slice()].concat()
}

fn generate(json_path: &PathBuf, output_path: &PathBuf) {
    let vk: Value = serde_json::from_slice(&fs::read(json_path).expect("read verifying key"))
        .expect("parse verifying key");
    let ic = vk["IC"].as_array().expect("missing IC array");
    assert_eq!(ic.len(), vk["nPublic"].as_u64().expect("missing nPublic") as usize + 1);
    let ic_arrays = ic.iter().map(|point| format!("{:?}", g1(point)))
        .collect::<Vec<_>>().join(",\n        ");
    let source = format!(
        "use groth16_solana::groth16::Groth16Verifyingkey;\n\
         pub const VERIFYINGKEY: Groth16Verifyingkey<'static> = Groth16Verifyingkey {{\n\
         nr_pubinputs: {},\n\
         vk_alpha_g1: {:?},\n\
         vk_beta_g2: {:?},\n\
         vk_gamme_g2: {:?},\n\
         vk_delta_g2: {:?},\n\
         vk_ic: &[\n        {}\n    ],\n}};\n",
        ic.len() - 1,
        g1(&vk["vk_alpha_1"]),
        g2(&vk["vk_beta_2"]),
        g2(&vk["vk_gamma_2"]),
        g2(&vk["vk_delta_2"]),
        ic_arrays,
    );
    fs::write(output_path, source).expect("write generated verifying key");
}

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("build");
    let mode = env::var("ZYNULL_VK_MODE").unwrap_or_else(|_| "development".to_owned());
    assert!(mode == "development" || mode == "production-candidate", "invalid verifying-key build mode");
    println!("cargo:rerun-if-env-changed=ZYNULL_VK_MODE");
    let mut selected_hashes = Vec::new();
    for (name, output, public_count, path_var, hash_var) in [
        ("normal", "vk_operation.rs", 10, "ZYNULL_NORMAL_VK_PATH", "ZYNULL_NORMAL_VK_SHA256"),
        ("exit", "vk_exit.rs", 5, "ZYNULL_EXIT_VK_PATH", "ZYNULL_EXIT_VK_SHA256")] {
        println!("cargo:rerun-if-env-changed={path_var}");
        println!("cargo:rerun-if-env-changed={hash_var}");
        let external = env::var(path_var).ok();
        let expected_hash = env::var(hash_var).ok();
        assert!(external.is_some() == expected_hash.is_some(), "external verifying-key path requires an exact SHA256 pin");
        if mode == "production-candidate" { assert!(external.is_some(), "production candidate requires both external verifying keys"); }
        let input = external.map(PathBuf::from).unwrap_or_else(|| root.join(format!("{name}_vk.json")));
        println!("cargo:rerun-if-changed={}", input.display());
        let bytes = fs::read(&input).expect("read V9 verifying key");
        let actual_hash = format!("{:x}", Sha256::digest(&bytes));
        if let Some(expected) = expected_hash {
            assert!(expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "noncanonical verifying-key SHA256");
            assert_eq!(actual_hash, expected, "external verifying key differs from its exact SHA256 pin");
        }
        let vk: Value = serde_json::from_slice(&bytes)
            .expect("parse V9 verifying key");
        assert_eq!(vk["nPublic"].as_u64(), Some(public_count), "wrong V9 verifying-key arity");
        assert_eq!(vk["protocol"].as_str(), Some("groth16"), "wrong proof protocol");
        assert_eq!(vk["curve"].as_str(), Some("bn128"), "wrong proof curve");
        if mode == "production-candidate" {
            // serde_json's map representation is sorted here. Hash only the
            // actual verifier inputs so added JSON metadata cannot bypass the
            // known-development-key block, even if dev files are absent.
            let mut coordinates = serde_json::Map::new();
            for key in ["protocol", "curve", "nPublic", "vk_alpha_1", "vk_beta_2", "vk_gamma_2", "vk_delta_2", "IC"] {
                coordinates.insert(key.to_owned(), vk[key].clone());
            }
            let coordinate_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&coordinates).expect("serialize VK coordinates")));
            assert!(![
                "658da46973481f1295f43addc63cb9e710ef36791a2d457d65c2c777f61560b0",
                "c558f3d92478dcab4fb6cb99a75f045708f617537608a2ab2e19f581b1c64946"
            ].contains(&coordinate_hash.as_str()), "known disposable development verifying key cannot be used in production candidate");
        }
        selected_hashes.push(format!("\"{name}\":\"{actual_hash}\""));
        generate(&input, &out.join(output));
    }
    fs::write(out.join("vk-build-inputs.json"), format!("{{\"mode\":\"{mode}\",\"keys\":{{{}}}}}\n", selected_hashes.join(","))).expect("write verifying-key input evidence");
}
