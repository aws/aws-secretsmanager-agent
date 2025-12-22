#![no_main]

use libfuzzer_sys::fuzz_target;
use aws_secretsmanager_agent::internal::parse::GSVQuery;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Skip inputs with null bytes since they're invalid in HTTP contexts
    if data.contains(&0) {
        return;
    }
    
    if let Ok(fuzz_str) = str::from_utf8(data) {
        // Test different URI parsing scenarios with fuzzed input
        let test_scenarios = vec![
            // Test secret ID fuzzing
            format!("/secretsmanager/get?secretId={}", fuzz_str),
            // Test path-based requests
            format!("/v1/{}", fuzz_str),
            // Test query parameters
            format!("/secretsmanager/get?secretId=test&refreshNow={}", fuzz_str),
            format!("/secretsmanager/get?secretId=test&versionId={}", fuzz_str),
            format!("/secretsmanager/get?secretId=test&versionStage={}", fuzz_str),
            // Test malformed URIs
            format!("/secretsmanager/get?{}", fuzz_str),
            format!("/v1/test?{}", fuzz_str),
        ];
        
        for uri_str in test_scenarios {
            // Test query-style parsing
            let _ = GSVQuery::try_from_query(&uri_str);
            
            // Test path-style parsing
            let _ = GSVQuery::try_from_path_query(&uri_str, "/v1/");
            let _ = GSVQuery::try_from_path_query(&uri_str, "/secretsmanager/");
        }
        
        // Test edge cases with URL encoding and special characters
        if fuzz_str.len() < 100 {
            let encoded_tests = vec![
                format!("/secretsmanager/get?secretId={}&refreshNow=true", urlencoding::encode(fuzz_str)),
                format!("/v1/{}?versionStage=AWSCURRENT", urlencoding::encode(fuzz_str)),
            ];
            
            for encoded_uri in encoded_tests {
                let _ = GSVQuery::try_from_query(&encoded_uri);
                let _ = GSVQuery::try_from_path_query(&encoded_uri, "/v1/");
            }
        }
    }
});