# LiteBox Runner for Newlib

This crate provides a runtime environment for applications using Newlib's static libc (libc.a) with LiteBox. It initializes the platform, filesystem, and handles POSIX stubs.

## Overview

The `litebox_runner_newlib` crate serves as the initialization (and C-library backend) layer for LiteBox when used with Newlib. 
It provides an initialization function that sets up the necessary environment for applications to run.
It also provides backend implementation for POSIX stubs.

## Usage

This crate is compiled as a static library (`liblitebox_newlibrunner.a`) and is intended to be linked with applications that use Newlib's libc.

## Target Architecture

The target architecture (ideally) should be named as x86_64-litebox (or x86_64-unknown-none).
For now, I would simply use native gnu-linux target.
