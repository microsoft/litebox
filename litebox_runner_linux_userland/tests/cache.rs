// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct CacheEntry {
    input_summaries: Vec<String>,
    output_summary: String,
    command_hash: String,
}

impl CacheEntry {
    fn from_inputs_output_and_command(
        input_paths: &[&Path],
        output_path: &Path,
        command: &str,
    ) -> std::io::Result<Self> {
        let mut input_summaries = Vec::new();

        for input_path in input_paths {
            let summary = compute_file_summary(input_path)?;
            input_summaries.push(summary);
        }

        let output_summary = compute_file_summary(output_path)?;
        let command_hash = compute_string_hash(command);

        Ok(Self {
            input_summaries,
            output_summary,
            command_hash,
        })
    }

    fn matches_inputs_and_command(
        &self,
        input_paths: &[&Path],
        command: &str,
    ) -> std::io::Result<bool> {
        if input_paths.len() != self.input_summaries.len() {
            return Ok(false);
        }

        let command_hash = compute_string_hash(command);
        if command_hash != self.command_hash {
            return Ok(false);
        }

        for (i, input_path) in input_paths.iter().enumerate() {
            let current_summary = compute_file_summary(input_path)?;
            if current_summary != self.input_summaries[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn output_still_valid(&self, output_path: &Path) -> std::io::Result<bool> {
        if !output_path.exists() {
            return Ok(false);
        }

        let current_summary = compute_file_summary(output_path)?;
        Ok(current_summary == self.output_summary)
    }

    fn save_to_file(&self, cache_path: &Path) -> std::io::Result<()> {
        let mut file = std::fs::File::create(cache_path)?;

        for summary in &self.input_summaries {
            writeln!(file, "input:{summary}")?;
        }
        writeln!(file, "output:{}", self.output_summary)?;
        writeln!(file, "command:{}", self.command_hash)?;

        Ok(())
    }

    fn load_from_file(cache_path: &Path) -> std::io::Result<Option<Self>> {
        if !cache_path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(cache_path)?;
        let mut input_summaries = Vec::new();
        let mut output_summary = None;
        let mut command_hash = None;

        for line in content.lines() {
            if let Some(summary) = line.strip_prefix("input:") {
                input_summaries.push(summary.to_string());
            } else if let Some(summary) = line.strip_prefix("output:") {
                output_summary = Some(summary.to_string());
            } else if let Some(hash) = line.strip_prefix("command:") {
                command_hash = Some(hash.to_string());
            }
        }

        if let (Some(output_summary), Some(command_hash)) = (output_summary, command_hash) {
            Ok(Some(Self {
                input_summaries,
                output_summary,
                command_hash,
            }))
        } else {
            Ok(None)
        }
    }
}

fn compute_file_summary(path: &Path) -> std::io::Result<String> {
    let metadata = std::fs::metadata(path)?;
    let mtime = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let size = metadata.len();
    Ok(format!("{}:{}", mtime.as_nanos(), size))
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
