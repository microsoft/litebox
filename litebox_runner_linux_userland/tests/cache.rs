use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct CacheEntry {
    input_hashes: Vec<String>,
    output_hash: String,
    command_hash: String,
}

impl CacheEntry {
    fn from_inputs_output_and_command(
        input_paths: &[&Path],
        output_path: &Path,
        command: &str,
    ) -> std::io::Result<Self> {
        let mut input_hashes = Vec::new();

        for input_path in input_paths {
            let hash = compute_file_hash(input_path)?;
            input_hashes.push(hash);
        }

        let output_hash = compute_file_hash(output_path)?;
        let command_hash = compute_string_hash(command);

        Ok(Self {
            input_hashes,
            output_hash,
            command_hash,
        })
    }

    fn matches_inputs_and_command(
        &self,
        input_paths: &[&Path],
        command: &str,
    ) -> std::io::Result<bool> {
        if input_paths.len() != self.input_hashes.len() {
            return Ok(false);
        }

        let command_hash = compute_string_hash(command);
        if command_hash != self.command_hash {
            return Ok(false);
        }

        for (i, input_path) in input_paths.iter().enumerate() {
            let current_hash = compute_file_hash(input_path)?;
            if current_hash != self.input_hashes[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn output_still_valid(&self, output_path: &Path) -> std::io::Result<bool> {
        if !output_path.exists() {
            return Ok(false);
        }

        let current_hash = compute_file_hash(output_path)?;
        Ok(current_hash == self.output_hash)
    }

    fn save_to_file(&self, cache_path: &Path) -> std::io::Result<()> {
        let mut file = std::fs::File::create(cache_path)?;

        for hash in &self.input_hashes {
            writeln!(file, "input:{hash}")?;
        }
        writeln!(file, "output:{}", self.output_hash)?;
        writeln!(file, "command:{}", self.command_hash)?;

        Ok(())
    }

    fn load_from_file(cache_path: &Path) -> std::io::Result<Option<Self>> {
        if !cache_path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(cache_path)?;
        let mut input_hashes = Vec::new();
        let mut output_hash = None;
        let mut command_hash = None;

        for line in content.lines() {
            if let Some(hash) = line.strip_prefix("input:") {
                input_hashes.push(hash.to_string());
            } else if let Some(hash) = line.strip_prefix("output:") {
                output_hash = Some(hash.to_string());
            } else if let Some(hash) = line.strip_prefix("command:") {
                command_hash = Some(hash.to_string());
            }
        }

        if let (Some(output_hash), Some(command_hash)) = (output_hash, command_hash) {
            Ok(Some(Self {
                input_hashes,
                output_hash,
                command_hash,
            }))
        } else {
            Ok(None)
        }
    }
}

fn compute_file_hash(path: &Path) -> std::io::Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

fn compute_string_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn get_cache_path(output_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.cache-checksum", output_path.display()))
}

pub fn is_cached_and_valid(
    input_paths: &[&Path],
    output_path: &Path,
    command: &str,
) -> std::io::Result<bool> {
    let cache_path = get_cache_path(output_path);

    if let Some(cache_entry) = CacheEntry::load_from_file(&cache_path)?
        && cache_entry.matches_inputs_and_command(input_paths, command)?
        && cache_entry.output_still_valid(output_path)?
    {
        return Ok(true);
    }

    Ok(false)
}

pub fn create_cache_entry(
    input_paths: &[&Path],
    output_path: &Path,
    command: &str,
) -> std::io::Result<()> {
    let cache_path = get_cache_path(output_path);
    let cache_entry =
        CacheEntry::from_inputs_output_and_command(input_paths, output_path, command)?;
    cache_entry.save_to_file(&cache_path)?;
    Ok(())
}
