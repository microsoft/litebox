# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

{ pkgs, ... }:
{
  projectRootFile = "flake.nix";

  settings.formatter.verusfmt = {
    command = "${pkgs.verusfmt}/bin/verusfmt";
    options = [ "--verus-only" ];
    includes = [
      "dev_tools/true-tales/src/*.rs"
      "dev_tools/true-tales/**/*.rs"
      "litebox/src/platform/true_tales_model/*.rs"
      "litebox/src/platform/true_tales_model/**/*.rs"
    ];
  };

  programs.nixfmt.enable = true;
  programs.rustfmt = {
    enable = true;
    edition = "2024";
  };
}
