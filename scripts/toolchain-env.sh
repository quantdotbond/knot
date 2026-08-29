#!/usr/bin/env bash
# Pinned auxiliary toolchain for local reproduction of the CI checks that need
# tools beyond GCC/make/python3: clang (+libFuzzer, MSan), valgrind, clang-tidy,
# cppcheck, syft (SBOM), gitleaks, qemu-user and cross GCC for aarch64 and
# s390x (big-endian). Everything comes from one pinned nixpkgs revision so
# tool versions are identical across machines.
#
#   source scripts/toolchain-env.sh      # exports PATH additions if nix is available
#   scripts/toolchain-env.sh --print     # print the store paths (fetches on first use)
#
# Without nix, scripts/ci.sh discovers tools on PATH and marks the checks that
# need missing tools as "unsupported" (never as passed).
NIXPKGS_REV="c27cdad491a991b11ed731760aa2ef8db0cb0410"   # nixpkgs 2026-08 (nixos-unstable), pinned
NIXPKGS="github:NixOS/nixpkgs/${NIXPKGS_REV}"
KNOT_NIX_ATTRS=(clang_19 valgrind valgrind.dev clang-tools cppcheck syft gitleaks qemu-user
                pkgsCross.aarch64-multiplatform.buildPackages.gcc
                pkgsCross.s390x.buildPackages.gcc)

knot_nix_paths() {
    command -v nix >/dev/null 2>&1 || return 1
    local args=()
    for a in "${KNOT_NIX_ATTRS[@]}"; do args+=("${NIXPKGS}#${a}"); done
    nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths "${args[@]}" 2>/dev/null
}

if [ "${1:-}" = "--print" ]; then
    knot_nix_paths
else
    if _knot_paths="$(knot_nix_paths)" && [ -n "$_knot_paths" ]; then
        # bash and zsh compatible iteration (zsh does not word-split "$var")
        for p in $(printf '%s\n' "$_knot_paths"); do
            [ -d "$p/bin" ] && PATH="$p/bin:$PATH"
            [ -d "$p/include/valgrind" ] && export KNOT_VALGRIND_INCLUDE="$p/include"
        done
        export PATH
        export KNOT_TOOLCHAIN_PINNED="nixpkgs/${NIXPKGS_REV}"
        unset _knot_paths
    else
        echo "toolchain-env: nix not available; using tools on PATH" >&2
    fi
fi
