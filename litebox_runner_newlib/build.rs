pub fn main() {
    // Tell Cargo to re-run this build script if the target specification file changes
    println!("cargo:rerun-if-changed=x86_64-litebox.json");
    
    // Tell Cargo to link with the C standard library
    println!("cargo:rustc-link-lib=c");
    
    // Tell Cargo to link with the math library
    println!("cargo:rustc-link-lib=m");
    
    // Tell Cargo to use the static linking mode
    println!("cargo:rustc-link-arg=-static");
    
    // Tell Cargo to not use the standard library
    println!("cargo:rustc-link-arg=-nostdlib");
}
