use anyhow::Result;
use memmap2::Mmap;
use std::{env, fs, path::Path};

mod instruction_rewriter;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: syscall-rewriter <elf-file>");
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    let file_data = fs::read(path)?;
    let mmap = unsafe { Mmap::map(&fs::File::open(path)?)? };
    let obj_file = object::File::parse(&*mmap)?;

    instruction_rewriter::rewrite_syscalls(path, &obj_file, file_data)?;

    Ok(())
}