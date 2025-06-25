# LiteBox Runner for Newlib

This crate provides a runtime environment for applications using Newlib's static libc (libc.a) with LiteBox. It initializes the platform, filesystem, and registers the syscall handler.

## Overview

The `litebox_runner_newlib` crate serves as the initialization layer for LiteBox when used with Newlib. It provides a `_start` function that sets up the necessary environment for applications to run.

## Usage

This crate is compiled as a static library (`lib_litebox_newlib.a`) and is intended to be linked with applications that use Newlib's libc and the `litebox_shim_newlib` crate.

## Target Architecture

The target architecture is x86_64-litebox.
