// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Command-line arguments test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Parsing command-line arguments
//! - Accessing program name
//! - Handling various argument formats

use std::env;

fn main() {
    println!("=== Command-Line Arguments Test ===\n");
    
    // Get and display all arguments
    let args: Vec<String> = env::args().collect();
    
    println!("Number of arguments: {}", args.len());
    println!("\nProgram name (args[0]): {}", args.first().unwrap_or(&"<none>".to_string()));
    
    if args.len() > 1 {
        println!("\nCommand-line arguments:");
        for (i, arg) in args.iter().enumerate().skip(1) {
            println!("  Argument {}: '{}'", i, arg);
        }
    } else {
        println!("\nNo command-line arguments provided.");
        println!("Try running: program.exe arg1 \"arg with spaces\" arg3");
    }
    
    // Test environment program name
    println!("\nCurrent executable path:");
    match env::current_exe() {
        Ok(path) => println!("  {}", path.display()),
        Err(e) => println!("  Error: {}", e),
    }
    
    println!("\n=== Arguments Test Complete ===");
}
