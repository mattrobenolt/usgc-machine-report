{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    mattware = {
      url = "github:mattrobenolt/nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    zon2nix = {
      url = "github:jcollie/zon2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      nixpkgs,
      mattware,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "aarch64-linux" ];

      perSystem =
        {
          system,
          inputs',
          ...
        }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ mattware.overlays.default ];
          };
          build = import ./nix/package.nix { inherit pkgs; };
        in
        {
          packages.usgc-machine-report = build.package;
          packages.default = build.package;
          # Regeneration tool for nix/zon-deps.nix. Never a build input: the
          # package build consumes only the committed generated file.
          packages.zon2nix = inputs'.zon2nix.packages.zon2nix;

          checks.package = build.package;

          formatter = pkgs.nixfmt-tree;

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              zig_0_16
              zls_0_16
              ziglint
              zigdoc
              hyperfine

              # machine_report.sh deps missing from default PATH
              procps # uptime -p (system uptime is coreutils, no -p)

              just # justfile is the tool contract
            ];
          };
        };
    };
}
