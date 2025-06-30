pub fn main() {
    // // Tell Cargo to re-run this build script if the target specification file changes
    // println!("cargo:rerun-if-changed=x86_64-litebox.json");
    #[cfg(feature = "platform_mock_nostd")]
    {
        println!("cargo:rustc-link-arg=-static");
        println!("cargo:rustc-link-arg=-nostdlib");
        // println!("cargo:rustc-link-lib=c");
        // println!("cargo:rustc-link-lib=m");
    }
    
    // DEBUG: compile this as a static library with libc
    #[cfg(not(feature = "platform_mock_nostd"))]
    {
        // Add library search paths
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-search=native=/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-lib=static=c");
        
        // Completely disable dynamic linking
        println!("cargo:rustc-link-arg=-static");
        println!("cargo:rustc-link-arg=-no-pie");
        println!("cargo:rustc-link-arg=-fno-pie");
        println!("cargo:rustc-link-arg=-fno-pic");

        // Remove all dynamic sections and symbols
        println!("cargo:rustc-link-arg=-Wl,--no-dynamic-linker");
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");
        println!("cargo:rustc-link-arg=-Wl,--strip-all");

        // Exclude dynamic linking related objects
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs=libdl.a");
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs=ld-linux-x86-64.so.2");

        // Remove dynamic sections entirely
        println!("cargo:rustc-link-arg=-Wl,--discard-all");
        println!("cargo:rustc-link-arg=-Wl,-s");  // Strip symbols
        
        // Set relocation model to static
        println!("cargo:rustc-codegen-opt=relocation-model=static");
    }
    // println!("cargo:rustc-link-lib=static=m");
}
