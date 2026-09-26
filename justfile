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

# Byte-for-byte comparison against the bash reference; volatile rows aside.
# The raw diff should show only load/memory/disk/uptime rows, the
# normalized diff should be empty.
golden: build
    #!/usr/bin/env bash
    set -euo pipefail
    bash machine_report.sh > /tmp/tr100_bash.txt 2>/dev/null
    ./zig-out/bin/usgc_machine_report > /tmp/tr100_zig.txt
    diff /tmp/tr100_bash.txt /tmp/tr100_zig.txt \
        && echo "raw diff: byte-identical"
    diff <(sed 's/[0-9]/N/g' /tmp/tr100_bash.txt) \
         <(sed 's/[0-9]/N/g' /tmp/tr100_zig.txt) \
        && echo "normalized diff: identical"

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

# Default: verify everything that can be verified.
default: test lint golden
