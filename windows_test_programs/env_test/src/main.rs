// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Environment variables test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Getting environment variables
//! - Setting environment variables
//! - Listing all environment variables

use std::env;

fn main() {
    println!("=== Environment Variables Test ===\n");
    
    // Test 1: Get common environment variables
    println!("Test 1: Getting common environment variables");
    
    let vars_to_check = vec!["PATH", "HOME", "USER", "TEMP", "TMP"];
    for var_name in vars_to_check {
        match env::var(var_name) {
            Ok(value) => {
                let value_len = value.len();
                let prefix_len = value_len.min(20);
                let prefix = &value[..prefix_len];
                let display_value = if value_len > prefix_len {
                    format!("{}... (length={})", prefix, value_len)
                } else {
                    format!("{} (length={})", prefix, value_len)
                };
                println!("  {}: {}", var_name, display_value);
            }
            Err(_) => println!("  {}: <not set>", var_name),
        }
    }
    
    // Test 2: Set and get a custom environment variable
    println!("\nTest 2: Setting custom environment variable");
    let test_var = "LITEBOX_TEST_VAR";
    let test_value = "Hello from LiteBox!";
    
    // SAFETY: Setting environment variable is safe in a single-threaded context
    // or when no other threads are accessing environment variables.
    unsafe {
        env::set_var(test_var, test_value);
    }
    println!("  Set {}='{}'", test_var, test_value);
    
    match env::var(test_var) {
        Ok(value) => {
            if value == test_value {
                println!("  ✓ Retrieved correct value: '{}'", value);
            } else {
                println!("  ✗ Value mismatch! Expected '{}', got '{}'", test_value, value);
            }
        }
        Err(e) => println!("  ✗ Failed to retrieve variable: {}", e),
    }
    
    // Test 3: Remove environment variable
    println!("\nTest 3: Removing environment variable");
    // SAFETY: Removing environment variable is safe in a single-threaded context
    // or when no other threads are accessing environment variables.
    unsafe {
        env::remove_var(test_var);
    }
    println!("  Removed {}", test_var);
    
    match env::var(test_var) {
        Ok(value) => println!("  ✗ Variable still exists with value: '{}'", value),
        Err(_) => println!("  ✓ Variable successfully removed"),
    }
    
    // Test 4: List all environment variables (limited to first 10)
    println!("\nTest 4: Listing environment variables (first 10)");
    let mut count = 0;
    for (key, value) in env::vars() {
        if count < 10 {
            let display_value = if value.len() > 50 {
                format!("{}...", &value[..50])
            } else {
                value
            };
            println!("  {}={}", key, display_value);
            count += 1;
        } else {
            break;
        }
    }
    println!("  ... ({} variables total)", env::vars().count());
    
    println!("\n=== Environment Variables Test Complete ===");
}
