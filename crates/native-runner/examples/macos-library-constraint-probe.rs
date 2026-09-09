//! Disposable native qualification executable; never packaged with the product.
#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert!((1..=2).contains(&args.len()));
    let hex = args[0].to_str().expect("hex digest");
    assert!(hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    let mut expected = [0_u8; 32];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    if let Some(replacement) = args.get(1) {
        // Change the pathname, not the running image. The public dynamic-code
        // check must distinguish these even when the replacement is validly signed.
        std::fs::rename(replacement, std::env::current_exe().unwrap()).unwrap();
    }
    if context_relay_native_runner::verify_current_library_constraint(&expected).is_err() {
        std::process::exit(20);
    }
    println!("verified running constraint");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("requires macOS");
    std::process::exit(1);
}
