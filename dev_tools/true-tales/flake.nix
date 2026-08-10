# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

{
  description = "true-tales Verification Framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;
        fenixPkgs = fenix.packages.${system};

        # Verus's pinned rust toolchain. The prebuilt `rust_verify` dynamically
        # loads this exact toolchain's `librustc_driver`. Bumping `verusVersion`
        # is what changes this toolchain; the two move together.
        rustVersion = "1.97.1";
        rust =
          (fenixPkgs.fromToolchainName {
            name = rustVersion;
            sha256 = "sha256-A1abGIbOtcBSdrUMhDGrER3pRM1hQP4fp9gh3Y4PKc8=";
          }).withComponents
            [
              "cargo"
              "clippy"
              "llvm-tools"
              "rust-analyzer"
              "rust-src"
              "rustc"
              "rustc-dev"
              "rustfmt"
            ];

        verusVersion = "0.2026.08.02.b677dd5";
        verusSystems = {
          "x86_64-linux" = {
            prebuiltArchive = pkgs.fetchurl {
              url = "https://github.com/verus-lang/verus/releases/download/release%2F${verusVersion}/verus-${verusVersion}-x86-linux.zip";
              hash = "sha256-THaSVuiI7oS96FquRNlcRrzLuM9w4dCfU3sNBf6WXe4=";
            };
            unpackDir = "verus-x86-linux";
          };
        };

        verus = pkgs.stdenv.mkDerivation {
          pname = "verus";
          version = verusVersion;

          src = verusSystems.${system}.prebuiltArchive;
          nativeBuildInputs = [
            pkgs.unzip
            pkgs.autoPatchelfHook
            pkgs.makeWrapper
          ];

          # Direct runtime deps of the bundled binaries (z3, rust_verify, the
          # launcher) so autoPatchelf can rewrite their interpreter/RPATH for the
          # Nix store.
          buildInputs = [
            pkgs.stdenv.cc.cc.lib
            pkgs.zlib
            pkgs.bzip2
          ];

          # `rust_verify` dynamically loads the rustup toolchain's
          # `librustc_driver` (and, through it, `libLLVM` and `libstd`) at runtime
          # via the launcher's LD_LIBRARY_PATH. Those are intentionally absent at
          # build time, so don't fail on them.
          autoPatchelfIgnoreMissingDeps = [
            "librustc_driver-*.so"
            "libstd-*.so"
            "libLLVM*.so"
          ];

          sourceRoot = verusSystems.${system}.unpackDir;

          installPhase = ''
            runHook preInstall
            mkdir -p $out/libexec/verus $out/bin
            cp -r ./* $out/libexec/verus/

            # The toolchain's `libLLVM` (pulled in by the runtime-loaded
            # `librustc_driver`) needs `libz.so.1`, which lives neither in the
            # rustup toolchain dir nor on a NixOS host's default search path. The
            # launcher *prepends* the toolchain dir to any inherited
            # LD_LIBRARY_PATH, so seeding it with zlib here makes that transitive
            # dependency resolve from the Nix store. The wrappers exec the real
            # launcher, whose canonical-path lookup still finds its siblings
            # (z3, rust_verify, vstd, ...).
            for BIN in verus cargo-verus; do
              makeWrapper $out/libexec/verus/$BIN $out/bin/$BIN \
                --prefix LD_LIBRARY_PATH : "${lib.makeLibraryPath [ pkgs.zlib ]}"
            done
            runHook postInstall
          '';

          meta = {
            description = "Verus: prebuilt SMT-based verifier for Rust";
            homepage = "https://github.com/verus-lang/verus";
            platforms = [ system ];
          };
        };

        verusEnvVars = {
          VERUS_USE_RUSTUP = "0";
          LD_LIBRARY_PATH = lib.makeLibraryPath [
            rust
            pkgs.zlib
          ];
        };

        verusShellEnv = ''
          # Instruct Verus to not use `rustup`:
          export VERUS_USE_RUSTUP="${verusEnvVars.VERUS_USE_RUSTUP}"
          # Allow verus to locate the Rust shared libraries:
          export LD_LIBRARY_PATH="${verusEnvVars.LD_LIBRARY_PATH}"
        '';

        # verusfmtVersion = "0.7.2";
        verusfmtVersion = "0.7.2-patched";

        verusfmt = pkgs.rustPlatform.buildRustPackage {
          pname = "verusfmt";
          version = verusfmtVersion;

          src = pkgs.fetchFromGitHub {
            owner = "verus-lang";
            repo = "verusfmt";
            rev = "af30648bdf1f1e4adbca5185f5d9a5d0261ddcde";
            hash = "sha256-FCgrKXPho4/LR6IVnexDn9z8EoKEK7jFH1QCNdva2CM=";
          };

          cargoHash = "sha256-QY8Sju3AzfGiSp6V2TsuUlT1EmW3rOdhp3EeU1XM3Bg=";

          buildNoDefaultFeatures = true;

          # `tests/rustfmt-does-not-touch-verus.rs` shells out to `rustfmt`, which
          # is not otherwise present in the build sandbox.
          nativeCheckInputs = [ pkgs.rustfmt ];

          meta = {
            description = "An opinionated formatter for Verus";
            homepage = "https://github.com/verus-lang/verusfmt";
            license = lib.licenses.mit;
            mainProgram = "verusfmt";
            platforms = lib.platforms.all;
          };
        };

        # To later migrate to an eachSystem defn
        treefmt = treefmt-nix.lib.evalModule (pkgs.extend (
          _self: _super: {
            inherit verusfmt;
          }
        )) ./treefmt.nix;

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rust);
        src = craneLib.cleanCargoSource ./.;

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          inherit src;
          strictDeps = true;
        };

        # Build *just* the cargo dependencies, so we can reuse all of that work
        # across builds.
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        verusVerifyCommand = "cargo verus verify --release --locked --all-targets";

        # Inspired by cargoClippy in upstream crane:
        cargoVerus =
          {
            cargoArtifacts,
            cargoVerusExtraArgs ? "--all-targets",
            cargoExtraArgs ? "--locked",
            ...
          }@origArgs:
          let
            args = builtins.removeAttrs origArgs [
              "cargoVerusExtraArgs"
              "cargoExtraArgs"
            ];
          in
          craneLib.mkCargoDerivation (
            args
            // verusEnvVars
            // {
              inherit cargoArtifacts;
              pnameSuffix = "-verus";
              buildPhaseCargoCommand = verusVerifyCommand;
              nativeBuildInputs = (origArgs.nativeBuildInputs or [ ]) ++ [ verus ];
            }
          );

        cargoArtifactsVerus = craneLib.buildDepsOnly (
          commonArgs
          // verusEnvVars
          // {
            src = null;
            dummySrc = craneLib.mkDummySrc (
              commonArgs
              // {
                # crane's default filter strips `package.metadata` from the dummy
                # Cargo.toml, dropping `[package.metadata.verus] verify = true` and
                # making `cargo verus` warn that no crate opted into verification.
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
                  // Verus refuses to run on a crate that has not imported
                  // `verus_builtin`, which `vstd::prelude` re-exports.
                  use vstd::prelude::*;
                '';
                dummyBuildrs = pkgs.writeText "verus-dummy-build.rs" ''
                  fn main() {}
                '';
              }
            );
            pname = "true-tales-verus";
            doCheck = false;
            nativeBuildInputs = [ verus ];
            buildPhaseCargoCommand = verusVerifyCommand;
          }
        );

        # Build the actual crate itself, reusing the dependency artifacts from
        # above.
        true-tales = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );
      in
      {
        packages = {
          inherit
            rust
            true-tales
            verus
            verusfmt
            ;
          default = true-tales;
        };

        devShells = {
          default = pkgs.mkShell {
            packages = [
              verus
              verusfmt
              rust
            ];

            shellHook = ''
              ${verusShellEnv}

              # Smoke-test:
              echo "verus $(verus --version 2>/dev/null | awk '/Version/ {print $2}') ready (run: verus ./src/lib.rs)"
            '';
          };

          rustup =
            let
              rustupToolchain = "${rustVersion}-${
                {
                  "x86_64-linux" = "x86_64-unknown-linux-gnu";
                }
                .${system}
              }";
            in
            pkgs.mkShell {
              # rustup supplies the exact toolchain Verus pins.
              packages = [
                verus
                verusfmt
                pkgs.rustup
              ];

              shellHook = ''
                # Ensure Verus's required toolchain (with the rustc-dev driver it
                # loads) is installed. This runs once; rustup caches it afterwards.
                if ! rustup toolchain list 2>/dev/null | grep -q '${rustupToolchain}'; then
                  echo "Installing rust toolchain ${rustupToolchain} required by Verus..."
                  rustup toolchain install ${rustupToolchain} \
                    --component rustc-dev --component llvm-tools --component rustfmt
                fi
                echo "verus $(verus --version 2>/dev/null | awk '/Version/ {print $2}') ready (run: verus ./src/lib.rs)"
              '';
            };
        };

        formatter = treefmt.config.build.wrapper;

        checks = {
          formatting = treefmt.config.build.check self;
          true-tales-verus = cargoVerus (
            commonArgs
            // {
              cargoArtifacts = cargoArtifactsVerus;
            }
          );

          true-tales-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
        };
      }
    );
}
