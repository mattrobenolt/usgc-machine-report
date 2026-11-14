set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Build the Debug binary.
build:
    zig build

# Build the ReleaseFast binary (the one worth shipping).
build-release:
    zig build -Doptimize=ReleaseFast

# Run the inline test suite.
test:
    zig build test

# Formatting and lint.
lint:
    zig fmt --check src/main.zig && ziglint src/main.zig

# Bench the bash script against the port.
bench: build-release
    hyperfine -N --warmup 10 --runs 50 \
        "./machine_report.sh" "./zig-out/bin/usgc_machine_report"

# Build the nix package (sandboxed, offline deps, ReleaseSafe).
nix-build:
    nix build .#default

[doc('Regenerate nix/zon-deps.nix from build.zig.zon after a dep bump.')]
[group('deps')]
bump-deps:
    nix run .#zon2nix -- --nix=nix/zon-deps.nix build.zig.zon
    nix build .#default

# Show the report.
run:
    zig build run

# The bash reference is no longer a byte-for-byte target: OS, CPU, volume
# and last-login rows deliberately report more than machine_report.sh did.
# `zig build test` holds the frame geometry.

[doc('Run the test suite and lint.')]
default: test lint
