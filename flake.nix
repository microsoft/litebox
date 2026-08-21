# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

{
  description = "LiteBox development checks";

  inputs = {
    true-tales.url = "path:./dev_tools/true-tales";
    crane.follows = "true-tales/crane";
    flake-utils.follows = "true-tales/flake-utils";
    nixpkgs.follows = "true-tales/nixpkgs";
    treefmt-nix.follows = "true-tales/treefmt-nix";
  };

  outputs =
    {
      self,
      crane,
      flake-utils,
      nixpkgs,
      treefmt-nix,
      true-tales,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;
        rust = true-tales.packages.${system}.rust;
        verus = true-tales.packages.${system}.verus;
        verusfmt = true-tales.packages.${system}.verusfmt;
        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rust);
        src = lib.cleanSourceWith {
          src = self;
          filter =
            path: type: craneLib.filterCargoSources path type || lib.hasSuffix "litebox/src/fs/test.tar" path;
        };

        treefmt = treefmt-nix.lib.evalModule (pkgs.extend (
          _self: _super: {
            inherit verusfmt;
          }
        )) ./treefmt.nix;

        commonArgs = {
          inherit src;
          pname = "litebox";
          version = "0.1.0";
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            cargoExtraArgs = "--locked -p litebox --features verify";
          }
        );

        verusEnvVars = {
          VERUS_USE_RUSTUP = "0";
          LD_LIBRARY_PATH = lib.makeLibraryPath [
            rust
            pkgs.zlib
          ];
        };

        verusVerifyCommand = "cargo verus verify --release --locked -p litebox --features verify --all-targets";

        verusDummyArgs = commonArgs // {
          # Preserve Verus's opt-in metadata in the dummy manifests so
          # dependency proofs are produced for the artifact cache.
          cleanCargoTomlFilter =
            path:
            craneLib.filters.cargoTomlDefault path
            || lib.lists.hasPrefix path [
              "package"
              "metadata"
              "verus"
            ]
            || lib.lists.hasPrefix [ "package" "metadata" "verus" ] path;

          dummyrs = pkgs.writeText "verus-dummy.rs" ''
            #[cfg(verus_dummy)]
            use vstd::prelude::*;
          '';
          dummyBuildrs = pkgs.writeText "verus-dummy-build.rs" ''
            fn main() {
                println!("cargo:rustc-check-cfg=cfg(verus_dummy)");
                if matches!(
                    std::env::var("CARGO_PKG_NAME").as_deref(),
                    Ok("litebox" | "true-tales")
                ) {
                    println!("cargo:rustc-cfg=verus_dummy");
                }
            }
          '';
        };

        verusDummySrc = craneLib.mkDummySrc verusDummyArgs;

        cargoArtifactsVerus = craneLib.buildDepsOnly (
          commonArgs
          // verusEnvVars
          // {
            src = null;
            dummySrc = verusDummySrc;
            pname = "litebox-verus";
            doCheck = false;
            nativeBuildInputs = [ verus ];
            buildPhaseCargoCommand = verusVerifyCommand;
          }
        );

        trueTalesSrc = lib.cleanSourceWith {
          src = true-tales;
          filter = craneLib.filterCargoSources;
        };

        trueTalesVerusSrc = craneLib.mkDummySrc (
          verusDummyArgs
          // {
            extraDummyScript = ''
              rm -rf $out/dev_tools/true-tales
              mkdir -p $out/dev_tools/true-tales
              cp -r ${trueTalesSrc}/. $out/dev_tools/true-tales/
            '';
          }
        );

        cargoArtifactsTrueTales = craneLib.mkCargoDerivation (
          commonArgs
          // verusEnvVars
          // {
            src = trueTalesVerusSrc;
            cargoArtifacts = cargoArtifactsVerus;
            pname = "true-tales-verus-cache";
            doCheck = false;
            nativeBuildInputs = [ verus ];
            buildPhaseCargoCommand = verusVerifyCommand;
          }
        );

      in
      {
        checks = {
          formatting = treefmt.config.build.check self;

          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "-p litebox --features verify --all-targets";
            }
          );

          verus = craneLib.mkCargoDerivation (
            commonArgs
            // verusEnvVars
            // {
              cargoArtifacts = cargoArtifactsTrueTales;
              pname = "litebox-verus";
              pnameSuffix = "-verify";
              nativeBuildInputs = [ verus ];
              buildPhaseCargoCommand = verusVerifyCommand;
            }
          );
        };

        formatter = treefmt.config.build.wrapper;
      }
    );
}
