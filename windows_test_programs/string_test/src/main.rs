// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! String operations test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - String allocation and manipulation
//! - CRT string functions
//! - Unicode string handling

fn main() {
    println!("=== String Operations Test ===\n");
    
    let mut passed = 0;
    let mut failed = 0;
    
    // Test 1: Basic string operations
    println!("Test 1: Basic string operations");
    let s1 = String::from("Hello");
    let s2 = String::from("World");
    let s3 = format!("{} {}", s1, s2);
    if s3 == "Hello World" {
        println!("  ✓ Concatenation: '{}' + '{}' = '{}'", s1, s2, s3);
        passed += 1;
    } else {
        println!("  ✗ Concatenation failed: expected 'Hello World', got '{}'", s3);
        failed += 1;
    }
    
    // Test 2: String comparison
    println!("\nTest 2: String comparison");
    let str_a = "litebox";
    let str_b = "litebox";
    let str_c = "LiteBox";
    
    if str_a == str_b {
        println!("  ✓ '{}' == '{}': true", str_a, str_b);
        passed += 1;
    } else {
        println!("  ✗ '{}' == '{}': false (expected true)", str_a, str_b);
        failed += 1;
    }
    
    if str_a != str_c {
        println!("  ✓ '{}' == '{}': false (case-sensitive)", str_a, str_c);
        passed += 1;
    } else {
        println!("  ✗ '{}' == '{}': true (expected false)", str_a, str_c);
        failed += 1;
    }
    
    if str_a.eq_ignore_ascii_case(str_c) {
        println!("  ✓ '{}' (case-insensitive) == '{}': true", str_a, str_c);
        passed += 1;
    } else {
        println!("  ✗ Case-insensitive comparison failed", );
        failed += 1;
    }
    
    // Test 3: String searching
    println!("\nTest 3: String searching");
    let haystack = "The quick brown fox jumps over the lazy dog";
    let needle = "fox";
    match haystack.find(needle) {
        Some(pos) if pos == 16 => {
            println!("  ✓ Found '{}' at position {}", needle, pos);
            passed += 1;
        }
        Some(pos) => {
            println!("  ✗ Found '{}' at position {} (expected 16)", needle, pos);
            failed += 1;
        }
        None => {
            println!("  ✗ '{}' not found", needle);
            failed += 1;
        }
    }
    
    // Test 4: String splitting
    println!("\nTest 4: String splitting");
    let csv = "apple,banana,cherry,date";
    let parts: Vec<&str> = csv.split(',').collect();
    if parts == vec!["apple", "banana", "cherry", "date"] {
        println!("  ✓ Split into {} parts correctly", parts.len());
        passed += 1;
    } else {
        println!("  ✗ Split failed: got {:?}", parts);
        failed += 1;
    }
    
    // Test 5: String trimming
    println!("\nTest 5: String trimming");
    let spaced = "   Hello World   ";
    let trimmed = spaced.trim();
    if trimmed == "Hello World" {
        println!("  ✓ Trimmed: '{}'", trimmed);
        passed += 1;
    } else {
        println!("  ✗ Trim failed: expected 'Hello World', got '{}'", trimmed);
        failed += 1;
    }
    
    // Test 6: Unicode strings
    println!("\nTest 6: Unicode string handling");
    let unicode = "Hello 世界 🦀";
    let byte_len = unicode.len();
    let char_count = unicode.chars().count();
    if byte_len == 17 && char_count == 10 {
        println!("  ✓ Unicode string: {} bytes, {} chars", byte_len, char_count);
        passed += 1;
    } else {
        println!("  ✗ Unicode handling issue: {} bytes (expected 17), {} chars (expected 10)", 
                 byte_len, char_count);
        failed += 1;
    }
    
    // Test 7: Case conversion
    println!("\nTest 7: Case conversion");
    let text = "LiteBox Sandbox";
    let upper = text.to_uppercase();
    let lower = text.to_lowercase();
    if upper == "LITEBOX SANDBOX" && lower == "litebox sandbox" {
        println!("  ✓ Case conversion: '{}' -> '{}' / '{}'", text, upper, lower);
        passed += 1;
    } else {
        println!("  ✗ Case conversion failed");
        failed += 1;
    }
    
    println!("\n=== String Operations Test Complete ===");
    println!("Results: {passed} passed, {failed} failed");
    
    if failed > 0 {
        std::process::exit(1);
    }
}
