#![no_main]

use libfuzzer_sys::fuzz_target;
use aws_secretsmanager_agent::{get_token, config::Config};
use std::fs;
use std::env;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Skip inputs with null bytes since env::set_var will panic on them
        // (env vars cannot contain null bytes in Rust)
        if s.contains('\0') {
            return;
        }
        
        // Test 1: Direct token value
        env::set_var("AWS_TOKEN", s);
        let config = Config::new(None).unwrap();
        let _ = get_token(&config);
        
        // Test 2: file:// path handling
        let file_path = format!("file://{}", s);
        env::set_var("AWS_TOKEN", &file_path);
        let config = Config::new(None).unwrap();
        let _ = get_token(&config);
        
        // Test 3: Create a temp file with the content and test reading it
        if s.len() < 1000 {
            let temp_path = format!("/tmp/fuzz_token_{}", std::process::id());
            if fs::write(&temp_path, s).is_ok() {
                let file_ref = format!("file://{}", temp_path);
                env::set_var("AWS_TOKEN", &file_ref);
                let config = Config::new(None).unwrap();
                let _ = get_token(&config);
                let _ = fs::remove_file(&temp_path);
            }
        }
        
        // Clean up
        env::remove_var("AWS_TOKEN");
    }
});
