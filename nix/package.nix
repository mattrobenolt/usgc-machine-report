# The build consumes only the committed generated deps file; zon2nix
# itself is a regeneration tool and never a build input (`just bump-deps`).
{ pkgs }:
let
  inherit (pkgs) lib;
  source = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.zig
      ../build.zig.zon
      ../src
    ];
  };
  dependencies = pkgs.callPackage ./zon-deps.nix { };
  package = pkgs.stdenv.mkDerivation {
    pname = "usgc-machine-report";
    version = "0.0.0";
    src = source;
    strictDeps = true;
    nativeBuildInputs = [ pkgs.zig_0_16.hook ];
    dontSetZigDefaultFlags = true;
    zigBuildFlags = [
      "-Doptimize=ReleaseSafe"
      "-Dcpu=baseline"
      "--system"
      "${dependencies}"
    ];
    doInstallCheck = true;
    installCheckPhase = ''
      runHook preInstallCheck
      # The report reads only /proc, /sys, /etc and fail-open sources,
      # so it renders in any sandbox; assert the frame and title survive.
      "$out/bin/usgc_machine_report" >report
      grep -F 'UNITED STATES GRAPHICS COMPANY' report
      grep -F 'TR-100 MACHINE REPORT' report
      test "$(grep -cF '│' report)" -ge 20
      runHook postInstallCheck
    '';
    meta = {
      description = "TR-100 machine report — fork-free login banner";
      homepage = "https://github.com/usgraphics/usgc-machine-report";
      license = lib.licenses.bsd3;
      mainProgram = "usgc_machine_report";
      platforms = [
        "aarch64-linux"
        "x86_64-linux"
      ];
    };
  };
in
{
  inherit package;
}
