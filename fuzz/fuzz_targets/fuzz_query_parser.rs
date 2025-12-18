#![no_main]

use libfuzzer_sys::fuzz_target;
use aws_secretsmanager_agent::GSVQuery;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(s) = std::str::from_utf8(data) {
        // Skip inputs with null bytes since they're invalid in HTTP contexts
        if s.contains('\0') {
            return;
        }
        
        // Test query-style parsing
        let _ = GSVQuery::try_from_query(s);
        
        // Test path-style parsing with common prefix
        let _ = GSVQuery::try_from_path_query(s, "/v1/");
        let _ = GSVQuery::try_from_path_query(s, "/secretsmanager/");
        
        // Test refresh value parsing
        let _ = aws_secretsmanager_agent::parse_refresh_value(s);
    }
});
