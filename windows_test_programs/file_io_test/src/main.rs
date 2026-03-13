// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Creating files
//! - Writing to files
//! - Reading from files
//! - Deleting files
//! - File existence checks

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

fn main() {
    println!("=== File I/O Test Suite ===\n");
    
    // Create a unique temp directory for this test run
    let temp_dir = std::env::temp_dir().join(format!(
        "litebox_file_io_test_{}",
        std::process::id()
    ));
    
    if let Err(e) = fs::create_dir_all(&temp_dir) {
        println!("✗ Failed to create test directory '{}': {}", temp_dir.display(), e);
        std::process::exit(1);
    }
    
    println!("Using test directory: {}", temp_dir.display());
    
    let test_file = temp_dir.join("test_file.txt");
    let test_content = "Hello from LiteBox file I/O test!";
    
    // Test 1: Create and write file
    println!("\nTest 1: Creating file...");
    match fs::File::create(&test_file) {
        Ok(mut file) => {
            println!("  ✓ File created successfully");
            
            print!("  Writing content...");
            match file.write_all(test_content.as_bytes()) {
                Ok(_) => println!(" ✓"),
                Err(e) => {
                    println!(" ✗ Failed: {}", e);
                    cleanup_and_exit(&temp_dir, 1);
                }
            }
        }
        Err(e) => {
            println!("  ✗ Failed to create file: {}", e);
            cleanup_and_exit(&temp_dir, 1);
        }
    }
    
    // Test 2: Read file
    println!("\nTest 2: Reading file...");
    match fs::File::open(&test_file) {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => {
                    println!("  ✓ Read {} bytes", contents.len());
                    if contents == test_content {
                        println!("  ✓ Content matches expected");
                    } else {
                        println!("  ✗ Content mismatch!");
                        println!("    Expected: {}", test_content);
                        println!("    Got: {}", contents);
                        cleanup_and_exit(&temp_dir, 1);
                    }
                }
                Err(e) => {
                    println!("  ✗ Failed to read: {}", e);
                    cleanup_and_exit(&temp_dir, 1);
                }
            }
        }
        Err(e) => {
            println!("  ✗ Failed to open file: {}", e);
            cleanup_and_exit(&temp_dir, 1);
        }
    }
    
    // Test 3: File metadata
    println!("\nTest 3: Checking file metadata...");
    match fs::metadata(&test_file) {
        Ok(metadata) => {
            println!("  ✓ File size: {} bytes", metadata.len());
            println!("  ✓ Is file: {}", metadata.is_file());
            println!("  ✓ Is directory: {}", metadata.is_dir());
        }
        Err(e) => {
            println!("  ✗ Failed to get metadata: {}", e);
            cleanup_and_exit(&temp_dir, 1);
        }
    }
    
    // Test 4: Delete file
    println!("\nTest 4: Deleting file...");
    match fs::remove_file(&test_file) {
        Ok(_) => {
            println!("  ✓ File deleted successfully");
            
            // Verify deletion
            if !test_file.exists() {
                println!("  ✓ File no longer exists");
            } else {
                println!("  ✗ File still exists after deletion!");
                cleanup_and_exit(&temp_dir, 1);
            }
        }
        Err(e) => {
            println!("  ✗ Failed to delete file: {}", e);
            cleanup_and_exit(&temp_dir, 1);
        }
    }
    
    // Test 5: Directory operations
    println!("\nTest 5: Directory operations...");
    let test_dir = temp_dir.join("test_subdirectory");
    
    print!("  Creating subdirectory...");
    match fs::create_dir(&test_dir) {
        Ok(_) => {
            println!(" ✓");
            
            // Create a file in the directory
            let nested_file = test_dir.join("nested.txt");
            if let Ok(mut file) = fs::File::create(&nested_file) {
                let _ = file.write_all(b"nested file content");
                println!("  ✓ Created nested file");
            }
            
            // List directory contents
            print!("  Listing directory contents...");
            match fs::read_dir(&test_dir) {
                Ok(entries) => {
                    let count = entries.count();
                    println!(" ✓ ({} entries)", count);
                }
                Err(e) => {
                    println!(" ✗ Failed: {}", e);
                    cleanup_and_exit(&temp_dir, 1);
                }
            }
            
            // Clean up subdirectory
            print!("  Cleaning up subdirectory...");
            let _ = fs::remove_file(&nested_file);
            match fs::remove_dir(&test_dir) {
                Ok(_) => println!(" ✓"),
                Err(e) => {
                    println!(" ✗ Failed: {}", e);
                    cleanup_and_exit(&temp_dir, 1);
                }
            }
        }
        Err(e) => {
            println!(" ✗ Failed: {}", e);
            cleanup_and_exit(&temp_dir, 1);
        }
    }
    
    // Final cleanup
    println!("\n=== File I/O Test Complete ===");
    println!("Cleaning up test directory...");
    if let Err(e) = fs::remove_dir_all(&temp_dir) {
        println!("Warning: Failed to clean up test directory: {}", e);
    } else {
        println!("✓ Test directory cleaned up");
    }
}

fn cleanup_and_exit(temp_dir: &PathBuf, exit_code: i32) -> ! {
    println!("\nCleaning up test directory...");
    let _ = fs::remove_dir_all(temp_dir);
    std::process::exit(exit_code);
}
