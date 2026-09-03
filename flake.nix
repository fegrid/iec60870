{
  description = "fegrid-iec60870 — IEC 60870-5 protocol stack in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = { url = "github:oxalica/rust-overlay"; inputs.nixpkgs.follows = "nixpkgs"; };
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = { url = "github:cachix/git-hooks.nix"; inputs.nixpkgs.follows = "nixpkgs"; };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, pre-commit-hooks }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        stableToolchain = pkgs.rust-bin.stable."1.97.1".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" "llvm-tools-preview" ];
        };
        nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (t: t.default.override {
          extensions = [ "rust-src" ];
        });

        commonDeps = with pkgs; [
          pkg-config
          clang
          libpcap
          tcpdump
          tshark
          cmake
          gcc
          libclang
          llvmPackages_19.libclang

          cargo-nextest
          cargo-audit
          taplo
          just
          cargo-deny
        ];

        preCommitHooks = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt.enable = true;
            clippy.settings.extraArgs = [ "--all-targets" "--" "-D" "warnings" ];
          };
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [ stableToolchain nightlyToolchain ] ++ commonDeps;
          shellHook = preCommitHooks.shellHook;
          CARGO_TARGET_DIR = "/tmp/fegrid-target";
          RUST_BACKTRACE = "1";
        };

        devShells.fuzz = pkgs.mkShell {
          packages = [ nightlyToolchain ] ++ commonDeps;
          shellHook = preCommitHooks.shellHook;
        };

        checks.pre-commit = preCommitHooks;
        formatter = pkgs.nixpkgs-fmt;
      });
}