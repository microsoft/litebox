// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Skill runner for executing agent skills in LiteBox
//!
//! This tool extracts and runs agent skills (as defined by the Agent Skills specification)
//! within a LiteBox sandboxed environment.

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Builder as TarBuilder;
use zip::ZipArchive;

/// Run agent skills in LiteBox sandbox
#[derive(Parser, Debug)]
#[command(name = "litebox_skill_runner")]
#[command(about = "Execute agent skills in LiteBox sandbox", long_about = None)]
struct CliArgs {
    /// Path to the .skill file (zip archive) or skill directory
    #[arg(value_hint = clap::ValueHint::FilePath)]
    skill_path: PathBuf,

    /// Script to execute within the skill (relative path from skill root)
    #[arg(long, short)]
    script: String,

    /// Additional arguments to pass to the script
    #[arg(trailing_var_arg = true)]
    script_args: Vec<String>,

    /// Path to litebox_runner_linux_userland binary
    #[arg(
        long,
        default_value = "../target/release/litebox_runner_linux_userland"
    )]
    runner_path: PathBuf,

    /// Python interpreter to use
    #[arg(long, default_value = "/usr/bin/python3")]
    python_path: PathBuf,
}

/// Skill metadata from SKILL.md frontmatter
#[derive(Debug, Deserialize)]
struct SkillMetadata {
    name: String,
    description: String,
    #[serde(default)]
    #[allow(dead_code)]
    license: Option<String>,
}

/// Represents an unpacked or extracted skill
struct Skill {
    /// Root directory of the skill
    root: PathBuf,
    /// Metadata from SKILL.md
    metadata: SkillMetadata,
    /// Whether this skill needs cleanup (was extracted from zip)
    needs_cleanup: bool,
}

impl Skill {
    /// Load a skill from a .skill file (zip) or directory
    fn load(path: &Path) -> Result<Self> {
        if path.is_file() {
            // Extract .skill zip file
            Self::from_skill_file(path)
        } else if path.is_dir() {
            // Use directory as-is
            Self::from_directory(path)
        } else {
            bail!(
                "Skill path must be a .skill file or directory: {}",
                path.display()
            );
        }
    }

    /// Extract a .skill file (zip) to a temporary directory
    fn from_skill_file(zip_path: &Path) -> Result<Self> {
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

        let file = File::open(zip_path)
            .with_context(|| format!("Failed to open skill file: {}", zip_path.display()))?;

        let mut archive =
            ZipArchive::new(file).context("Failed to read skill file as zip archive")?;

        // Extract all files
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = temp_dir.path().join(file.mangled_name());

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    fs::create_dir_all(p)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }

            // Set permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }

        let root = temp_dir.keep();
        let metadata = Self::read_metadata(&root)?;

        Ok(Self {
            root,
            metadata,
            needs_cleanup: true,
        })
    }

    /// Load a skill from an existing directory
    fn from_directory(dir_path: &Path) -> Result<Self> {
        let metadata = Self::read_metadata(dir_path)?;

        Ok(Self {
            root: dir_path.to_path_buf(),
            metadata,
            needs_cleanup: false,
        })
    }

    /// Read and parse SKILL.md metadata
    fn read_metadata(skill_root: &Path) -> Result<SkillMetadata> {
        let skill_md_path = skill_root.join("SKILL.md");
        let mut content = String::new();
        File::open(&skill_md_path)
            .with_context(|| format!("Failed to open SKILL.md at {}", skill_md_path.display()))?
            .read_to_string(&mut content)
            .context("Failed to read SKILL.md")?;

        // Extract YAML frontmatter between --- delimiters
        let frontmatter = Self::extract_frontmatter(&content)
            .context("Failed to extract YAML frontmatter from SKILL.md")?;

        serde_yaml::from_str(&frontmatter).context("Failed to parse YAML frontmatter")
    }

    /// Extract YAML frontmatter from markdown content
    fn extract_frontmatter(content: &str) -> Result<String> {
        let lines: Vec<&str> = content.lines().collect();

        if lines.is_empty() || !lines[0].trim().starts_with("---") {
            bail!("SKILL.md must start with YAML frontmatter (---)");
        }

        // Find the closing ---
        let end = lines[1..]
            .iter()
            .position(|line| line.trim().starts_with("---"))
            .context("YAML frontmatter must end with ---")?;

        Ok(lines[1..=end].join("\n"))
    }
}

impl Drop for Skill {
    fn drop(&mut self) {
        if self.needs_cleanup {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

/// Create a tar file containing the skill resources for litebox
fn create_skill_tar(skill: &Skill, output_tar: &Path) -> Result<()> {
    let tar_file = File::create(output_tar)
        .with_context(|| format!("Failed to create tar file: {}", output_tar.display()))?;

    let mut tar = TarBuilder::new(tar_file);

    // Add the entire skill directory to the tar file
    tar.append_dir_all("skill", &skill.root)
        .context("Failed to add skill directory to tar")?;

    tar.finish().context("Failed to finish tar file")?;

    Ok(())
}

/// Run a skill script in litebox
fn run_skill_script(args: &CliArgs, skill: &Skill, tar_path: &Path) -> Result<()> {
    // Construct the full script path within the skill
    let script_rel_path = Path::new("skill").join(&args.script);

    println!(
        "Running skill: {} ({})",
        skill.metadata.name, skill.metadata.description
    );
    println!("Script: {}", args.script);
    println!("Tar file: {}", tar_path.display());

    // Build the litebox runner command
    let mut cmd = Command::new(&args.runner_path);

    cmd.arg("--unstable")
        .arg("--initial-files")
        .arg(tar_path)
        .arg("--interception-backend")
        .arg("seccomp");

    // Determine the interpreter and arguments based on file extension
    let script_path_str = script_rel_path.to_string_lossy();

    if args.script.to_lowercase().ends_with(".py") {
        // Python script
        cmd.arg(&args.python_path).arg(script_path_str.to_string());
    } else if args.script.to_lowercase().ends_with(".sh") {
        // Shell script - note: this may not work due to shell limitation
        eprintln!("Warning: Shell scripts may not work due to litebox's lack of shell support");
        cmd.arg("/bin/sh").arg(script_path_str.to_string());
    } else {
        // Try to execute directly
        cmd.arg(script_path_str.to_string());
    }

    // Add script arguments
    for arg in &args.script_args {
        cmd.arg(arg);
    }

    println!("Executing: {cmd:?}");

    // Execute the command
    let status = cmd.status().context("Failed to execute litebox runner")?;

    if !status.success() {
        bail!("Script execution failed with status: {status}");
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // Load the skill
    let skill = Skill::load(&args.skill_path).context("Failed to load skill")?;

    println!("Loaded skill: {}", skill.metadata.name);
    println!("Description: {}", skill.metadata.description);

    // Create tar file with skill resources
    let tar_dir = tempfile::tempdir().context("Failed to create temporary directory for tar")?;
    let tar_path = tar_dir.path().join("skill.tar");

    create_skill_tar(&skill, &tar_path).context("Failed to create skill tar file")?;

    // Run the script in litebox
    run_skill_script(&args, &skill, &tar_path).context("Failed to run skill script")?;

    Ok(())
}
