# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# treefmt.nix
{ pkgs, ... }:
{
  # Used to find the project root
  projectRootFile = "flake.nix";

  # Verusfmt is not supported by default:
  settings.formatter.verusfmt = {
    command = "${pkgs.verusfmt}/bin/verusfmt";
    options = [
      "--verus-only"
      # Unsupported with verus-only:
      # "--edition" "2024"
    ];
    includes = [ "*.rs" ];
  };

  # programs.deadnix.enable = true;
  programs.nixfmt.enable = true;
  programs.toml-sort.enable = true;
  programs.rustfmt = {
    enable = true;
    edition = "2024";
  };
}
