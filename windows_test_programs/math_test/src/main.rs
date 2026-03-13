// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Math operations test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Floating-point arithmetic
//! - Integer arithmetic
//! - Math library functions

fn main() {
    println!("=== Math Operations Test ===\n");
    
    let mut passed = 0;
    let mut failed = 0;
    
    // Test 1: Integer arithmetic
    println!("Test 1: Integer arithmetic");
    let a = 42;
    let b = 17;
    
    if a + b == 59 && a - b == 25 && a * b == 714 && a / b == 2 && a % b == 8 {
        println!("  ✓ Integer operations: {a}+{b}=59, {a}-{b}=25, {a}*{b}=714, {a}/{b}=2, {a}%{b}=8");
        passed += 1;
    } else {
        println!("  ✗ Integer operations failed");
        failed += 1;
    }
    
    // Test 2: Floating-point arithmetic
    println!("\nTest 2: Floating-point arithmetic");
    let x = std::f64::consts::PI;
    let y = std::f64::consts::E;
    let sum = x + y;
    
    if (sum - 5.85987).abs() < 0.001 {
        println!("  ✓ Float addition: π + e ≈ {:.5}", sum);
        passed += 1;
    } else {
        println!("  ✗ Float addition failed: {:.5}", sum);
        failed += 1;
    }
    
    // Test 3: Math functions
    println!("\nTest 3: Math library functions");
    let sqrt_result = 16.0_f64.sqrt();
    let pow_result = 2.0_f64.powf(8.0);
    
    if (sqrt_result - 4.0).abs() < 0.0001 && (pow_result - 256.0).abs() < 0.0001 {
        println!("  ✓ sqrt(16.0) = {:.1}, pow(2.0, 8.0) = {:.1}", sqrt_result, pow_result);
        passed += 1;
    } else {
        println!("  ✗ Math functions failed");
        failed += 1;
    }
    
    let angle = 45.0_f64.to_radians();
    let sin_val = angle.sin();
    let expected_sin = std::f64::consts::FRAC_1_SQRT_2;
    if (sin_val - expected_sin).abs() < 0.0001 {
        println!("  ✓ sin(45°) ≈ {:.4}", sin_val);
        passed += 1;
    } else {
        println!("  ✗ sin(45°) failed: {:.4}", sin_val);
        failed += 1;
    }
    
    // Test 4: Special values
    println!("\nTest 4: Special floating-point values");
    if 42.0_f64.is_finite() && !42.0_f64.is_nan() && f64::NAN.is_nan() {
        println!("  ✓ Special values: 42.0 is finite, NaN is NaN");
        passed += 1;
    } else {
        println!("  ✗ Special values check failed");
        failed += 1;
    }
    
    // Test 5: Rounding
    println!("\nTest 5: Rounding operations");
    let value = 3.7_f64;
    let floor_result = value.floor();
    let ceil_result = value.ceil();
    let round_result = value.round();
    let trunc_result = value.trunc();
    
    if (floor_result - 3.0).abs() < 0.0001 
        && (ceil_result - 4.0).abs() < 0.0001 
        && (round_result - 4.0).abs() < 0.0001 
        && (trunc_result - 3.0).abs() < 0.0001 {
        println!("  ✓ Rounding: floor=3, ceil=4, round=4, trunc=3");
        passed += 1;
    } else {
        println!("  ✗ Rounding operations failed");
        failed += 1;
    }
    
    // Test 6: Bitwise operations
    println!("\nTest 6: Bitwise operations");
    let bits_a = 0b1010;
    let bits_b = 0b1100;
    
    if (bits_a & bits_b) == 0b1000 && (bits_a | bits_b) == 0b1110 && (bits_a ^ bits_b) == 0b0110 {
        println!("  ✓ Bitwise: AND=1000, OR=1110, XOR=0110");
        passed += 1;
    } else {
        println!("  ✗ Bitwise operations failed");
        failed += 1;
    }
    
    println!("\n=== Math Operations Test Complete ===");
    println!("Results: {passed} passed, {failed} failed");
    
    if failed > 0 {
        std::process::exit(1);
    }
}
