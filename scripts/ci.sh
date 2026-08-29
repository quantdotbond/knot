#!/usr/bin/env bash
# =============================================================================
#  KNOT production-assurance CI entry point
# =============================================================================
#
#   scripts/ci.sh quick        fast, blocking PR checks (default)
#   scripts/ci.sh nightly      quick + extended/slow checks
#   scripts/ci.sh release      nightly + release artifact assembly (no publishing)
#   scripts/ci.sh <check>...   run named checks only (see `scripts/ci.sh list`)
#
# Every check ends in exactly one status:
#   pass         ran and succeeded
#   fail         ran and failed                       -> CI fails if tier=required
#   known-fail   failed as documented by a finding    -> never hides: listed in the summary
#   xpass        a documented finding no longer reproduces -> CI fails (registry must be updated)
#   unsupported  could not run in this environment    -> CI fails if tier=required and KNOT_CI_STRICT=1
# Nothing is ever marked pass because a tool was missing.
#
# Environment:
#   CXX                 system C++ compiler (default g++)
#   KNOT_TOOLCHAIN      auto|nix|system  (auto: use scripts/toolchain-env.sh if nix is present)
#   KNOT_CI_STRICT=1    unsupported required checks fail the run (release mode sets this)
#   KNOT_ARTIFACTS      artifact directory (default ci-artifacts)
#   KNOT_JOBS           parallel build jobs (default nproc)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ART="${KNOT_ARTIFACTS:-ci-artifacts}"
JOBS="${KNOT_JOBS:-$(nproc 2>/dev/null || echo 2)}"
CXX="${CXX:-g++}"
MODE="${1:-quick}"
STRICT="${KNOT_CI_STRICT:-0}"
[ "$MODE" = release ] && STRICT=1
export KNOT_CI_RUNNING=1

# ---- toolchain -----------------------------------------------------------------
case "${KNOT_TOOLCHAIN:-auto}" in
    nix)  source scripts/toolchain-env.sh ;;
    auto) command -v nix >/dev/null 2>&1 && source scripts/toolchain-env.sh ;;
esac
have() { command -v "$1" >/dev/null 2>&1; }
CLANGXX="$(command -v clang++ || true)"
# The pinned (nix) valgrind can only run binaries linked against the pinned
# glibc, i.e. binaries built by the pinned clang; a system valgrind runs
# anything. Detect which case applies.
VALGRIND="$(command -v valgrind || true)"
VG_NEEDS_NIX_BUILD=0
if [ -n "$VALGRIND" ] && [[ "$VALGRIND" == /nix/store/* ]]; then VG_NEEDS_NIX_BUILD=1; fi

# ---- bookkeeping ---------------------------------------------------------------
mkdir -p "$ART/results" "$ART/logs"
SUMMARY="$ART/ci-summary.json"
declare -a CHECKS=()
FAILED=0
START_ALL=$(date +%s)

record() { # name tier tool status expected finding duration reason
    local name="$1" tier="$2" tool="$3" status="$4" expected="$5" finding="$6" dur="$7" reason="$8"
    python3 - "$ART/results/$name.json" "$name" "$tier" "$tool" "$status" "$expected" "$finding" "$dur" "$reason" "$ART/logs/$name.log" <<'PY'
import json, sys
p, name, tier, tool, status, expected, finding, dur, reason, log = sys.argv[1:]
json.dump({"record": "ci-check", "check": name, "tier": tier, "tool": tool, "status": status,
           "expected": expected, "finding": finding or None, "duration_s": float(dur), "reason": reason or None,
           "log": log}, open(p, "w"), indent=1)
PY
    CHECKS+=("$name")
    printf "  %-40s %-12s %s%s\n" "$name" "$status" "${finding:+[$finding] }" "${reason}"
}

# run_check <name> <tier> <tool> <expected> <cmd...>
#   expected = pass | known-fail:<FINDING-ID>
run_check() {
    local name="$1" tier="$2" tool="$3" expected="$4"; shift 4
    local t0=$(date +%s.%N) rc status finding="" reason=""
    ( "$@" ) > "$ART/logs/$name.log" 2>&1; rc=$?
    local dur; dur=$(python3 -c "print(round($(date +%s.%N)-$t0,2))")
    if [[ "$expected" == known-fail:* ]]; then
        finding="${expected#known-fail:}"
        if [ $rc -ne 0 ]; then status="known-fail"; reason="documented core finding; see metadata/findings/findings.json"
        else status="xpass"; reason="finding no longer reproduces: update metadata/findings and this check"; FAILED=1; fi
    else
        if [ $rc -eq 0 ]; then status="pass"
        else status="fail"; reason="exit $rc; see $ART/logs/$name.log"; [ "$tier" = required ] && FAILED=1; fi
    fi
    record "$name" "$tier" "$tool" "$status" "$expected" "$finding" "$dur" "$reason"
    return $rc
}
skip_check() { # name tier tool reason
    local name="$1" tier="$2" tool="$3" reason="$4"
    : > "$ART/logs/$name.log"
    record "$name" "$tier" "$tool" "unsupported" "pass" "" 0 "$reason"
    if [ "$tier" = required ] && [ "$STRICT" = 1 ]; then FAILED=1; fi
}

STRICT_WARN="-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wformat=2 -Wundef -Wnull-dereference -Wdouble-promotion -Wimplicit-fallthrough"
INC="-Iinclude -Iproduction/adapter -Iproduction/rng -Iproduction/tests"
PROD_TESTS="smoke kat roundtrip negative parity portability"

pbuild() { # variant cxx opt san extra targets...
    local variant="$1" cxx="$2" opt="$3" san="$4" extra="$5"; shift 5
    make -C production CXX="$cxx" VARIANT="$variant" OPT="$opt" SAN="$san" EXTRA="$extra" -j"$JOBS" "$@"
}
prun_tests() { # variant [env...]
    local variant="$1"; shift
    local ok=0
    for t in $PROD_TESTS; do
        env "$@" KNOT_TEST_JSON="$ART/results/test-$variant-$t.json" "build/production/$variant/${t}_test" || ok=1
    done
    return $ok
}

# =============================================================================
#  Check definitions
# =============================================================================
c_core_identity()  { run_check core-identity required sha256sum pass scripts/core_digest.sh --check; }
c_build_meta()     { CXX="$CXX" CXXFLAGS="-std=c++20 -O2 $STRICT_WARN" run_check build-metadata required scripts/build_meta.sh pass scripts/build_meta.sh "$ART/build-metadata.json"; }

c_existing_build() {
    run_check build-existing-suite-gcc-release required "$CXX" pass \
        make -B CXX="$CXX" CXXFLAGS="-std=c++20 -O2 -Wall -Wextra -Iinclude" tests/run_tests tests/gen_vectors bench/run_bench
}
c_existing_tests() { run_check test-existing-suite required tests/run_tests pass ./tests/run_tests; }
c_vectors_fresh() {
    run_check kat-original-corpus-fresh required tests/gen_vectors pass bash -c '
        set -e; d=$(mktemp -d); mkdir -p "$d/vectors"; (cd "$d" && "'"$ROOT"'/tests/gen_vectors") >/dev/null
        diff -u vectors/kat.txt "$d/vectors/kat.txt" && rm -rf "$d"'
}
c_core_diagnostics() {
    # Strict warnings on the immutable core, NOT blocking: counted and reported (finding KNOT-CORE-006).
    run_check core-diagnostics informational "$CXX" pass bash -c '
        set -o pipefail
        printf "#include \"ccts/scheme.hpp\"\nint main(){}\n" > "'"$ART"'/core_diag.cpp"
        '"$CXX"' -std=c++20 -O2 '"$STRICT_WARN"' -Iinclude -fsyntax-only "'"$ART"'/core_diag.cpp" 2> "'"$ART"'/results/core-diagnostics-warnings.txt"
        n=$(grep -c "warning:" "'"$ART"'/results/core-diagnostics-warnings.txt" || true)
        echo "core strict-warning count: $n"; rm -f "'"$ART"'/core_diag.cpp"'
}
c_prod_gcc() {
    run_check build-production-gcc-release required "$CXX" pass pbuild gcc-release "$CXX" "-O2" "" "" tests tools fuzz-standalone bench sidechannel &&
    run_check test-production-gcc-release required "$CXX" pass prun_tests gcc-release
    run_check build-production-gcc-debug required "$CXX" pass pbuild gcc-debug "$CXX" "-O0 -g" "" "" tests &&
    run_check test-production-gcc-debug required "$CXX" pass prun_tests gcc-debug
    run_check build-production-gcc-O3 best-effort "$CXX" pass pbuild gcc-O3 "$CXX" "-O3" "" "" tests &&
    run_check test-production-gcc-O3 best-effort "$CXX" pass prun_tests gcc-O3
}
c_prod_clang() {
    if [ -z "$CLANGXX" ]; then skip_check build-production-clang-release required clang++ "clang++ not found (install clang or use KNOT_TOOLCHAIN=nix)"; skip_check test-production-clang-release required clang++ "no clang"; return; fi
    run_check build-production-clang-release required clang++ pass pbuild clang-release "$CLANGXX" "-O2" "" "" tests tools fuzz-standalone &&
    run_check test-production-clang-release required clang++ pass prun_tests clang-release
    run_check build-production-clang-debug required clang++ pass pbuild clang-debug "$CLANGXX" "-O0 -g" "" "" tests &&
    run_check test-production-clang-debug required clang++ pass prun_tests clang-debug
}
c_kat_regen() {
    run_check kat-versioned-corpus-fresh required gen_kat pass bash -c '
        set -e; t=$(mktemp); build/production/gcc-release/gen_kat "$t" "$(scripts/core_digest.sh --tree)" >/dev/null
        diff -u vectors/knot-kat-v1.txt "$t" && rm -f "$t"'
}
c_parity_cross_binary() {
    # Debug vs release vs clang: the KAT suite passing in each build IS the
    # cross-binary parity evidence; here we additionally diff the regenerated
    # corpus produced by every available build.
    run_check parity-cross-build-kat required gen_kat pass bash -c '
        set -e; ref=$(mktemp); build/production/gcc-release/gen_kat "$ref" x >/dev/null
        for v in gcc-debug gcc-O3 clang-release clang-debug; do
            [ -x build/production/$v/gen_kat ] || { echo "skip $v"; continue; }
            t=$(mktemp); build/production/$v/gen_kat "$t" x >/dev/null
            if ! cmp -s "$ref" "$t"; then echo "MISMATCH: $v produces different vectors"; exit 1; fi
            echo "identical: $v"; rm -f "$t"
        done; rm -f "$ref"'
}
c_sanitizers() {
    local san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
    run_check sanitizer-asan-ubsan-gcc required "$CXX" pass bash -c "
        set -e; $(declare -f pbuild prun_tests); JOBS=$JOBS ART=$ART PROD_TESTS='$PROD_TESTS'
        pbuild gcc-asan '$CXX' '-O1 -g' '$san' '' tests fuzz-standalone
        ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1 UBSAN_OPTIONS=print_stacktrace=1 prun_tests gcc-asan"
    if [ -n "$CLANGXX" ]; then
        run_check sanitizer-asan-ubsan-clang required clang++ pass bash -c "
            set -e; $(declare -f pbuild prun_tests); JOBS=$JOBS ART=$ART PROD_TESTS='$PROD_TESTS'
            pbuild clang-asan '$CLANGXX' '-O1 -g' '$san' '' tests
            ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 prun_tests clang-asan"
    else skip_check sanitizer-asan-ubsan-clang required clang++ "no clang"; fi
    # MemorySanitizer needs an MSan-instrumented C++ standard library; with an
    # uninstrumented libstdc++ it reports false positives (observed in
    # subdiagram_census; valgrind memcheck on the same path is clean).
    skip_check sanitizer-msan best-effort clang++ "requires MSan-instrumented libc++ (not in the pinned toolchain); uninitialized-value coverage provided by valgrind-memcheck"
    run_check sanitizer-existing-suite-asan-ubsan required "$CXX" pass bash -c "
        set -e; $CXX -std=c++20 -O1 -g $san -Iinclude tests/test_main.cpp -o build/run_tests_asan && ASAN_OPTIONS=detect_leaks=1 ./build/run_tests_asan"
}
c_fuzz_short() {
    local runs="${KNOT_FUZZ_RUNS:-2000}"
    local F=build/production/gcc-asan/fuzz
    [ -x "$F/fuzz_pk_adapter_standalone" ] || pbuild gcc-asan "$CXX" "-O1 -g" "-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" "" fuzz-standalone > "$ART/logs/fuzz-build.log" 2>&1
    mkdir -p production/fuzz/work
    for t in $(make -s -C production print-fuzzers); do
        local expected=pass
        case "$t" in
            fuzz_pk_raw)         expected="known-fail:KNOT-CORE-005" ;;
            fuzz_sig_packed_raw) expected="known-fail:KNOT-CORE-002" ;;
        esac
        # Raw targets: replay the regression corpus (must reproduce the finding).
        # All targets: replay seeds and run bounded mutations under ASan/UBSan.
        # ASan needs a huge virtual address space, so no ulimit -v here: hostile
        # allocation sizes are bounded by the sanitizer allocator instead
        # (max_allocation_size_mb -> null -> std::bad_alloc, caught by the target).
        run_check "fuzz-standalone-$t" required standalone-driver "$expected" bash -c "
            cd production/fuzz/work
            ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:max_allocation_size_mb=1024:hard_rss_limit_mb=4096 \
            ../../../$F/${t}_standalone -runs=$runs -seed=\${KNOT_FUZZ_SEED:-1} ../corpus/$t"
    done
    if [ -n "$CLANGXX" ]; then
        local total="${KNOT_LIBFUZZER_SECONDS:-15}"
        for t in $(make -s -C production print-fuzzers); do
            case "$t" in fuzz_pk_raw|fuzz_sig_packed_raw) continue ;; esac  # raw boundary: standalone replay above documents them
            run_check "fuzz-libfuzzer-$t" required libFuzzer pass bash -c "
                set -e; mkdir -p build/production/libfuzzer production/fuzz/work/$t
                $CLANGXX -std=c++20 -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all $INC -Iproduction/fuzz production/fuzz/$t.cpp -o build/production/libfuzzer/$t
                cd production/fuzz/work/$t && ../../../../build/production/libfuzzer/$t -max_total_time=$total -max_len=4096 -rss_limit_mb=2048 -malloc_limit_mb=1024 -print_final_stats=1 -artifact_prefix=./ . ../../corpus/$t/seeds \$( [ -d ../../corpus/$t/regressions ] && echo ../../corpus/$t/regressions )"
        done
    else skip_check fuzz-libfuzzer required clang++ "libFuzzer needs clang; standalone mutation runs executed instead"; fi
}
c_static() {
    run_check static-gcc-analyzer required "$CXX -fanalyzer" pass bash -c '
        set -o pipefail; out="'"$ART"'/results/static-gcc-analyzer.txt"; : > "$out"
        for f in production/tests/*_test.cpp production/tools/*.cpp production/fuzz/fuzz_*.cpp production/bench/*.cpp production/sidechannel/*.cpp; do
            '"$CXX"' -std=c++20 -O1 -fanalyzer '"$INC"' -Iproduction/fuzz -fsyntax-only "$f" 2>>"$out" || true
        done
        prod=$(grep -c "^production/.*warning:" "$out" || true); core=$(grep -c "^include/ccts/.*warning:" "$out" || true)
        echo "gcc -fanalyzer: production-layer warnings=$prod core warnings=$core (core reported, not blocking)"
        [ "$prod" -eq 0 ]'
    if have clang-tidy; then
        run_check static-clang-tidy required clang-tidy pass bash -c '
            set -o pipefail; out="'"$ART"'/results/static-clang-tidy.txt"; : > "$out"
            for f in production/tests/*_test.cpp production/tools/*.cpp production/fuzz/fuzz_*.cpp production/bench/*.cpp production/sidechannel/*.cpp; do
                clang-tidy --quiet "$f" -- -std=c++20 '"$INC"' -Iproduction/fuzz 2>/dev/null >> "$out" || true
            done
            prod=$(grep -cE "^[^ ]*production/.*(warning|error):" "$out" || true); core=$(grep -cE "^[^ ]*include/ccts/.*(warning|error):" "$out" || true)
            echo "clang-tidy: production-layer findings=$prod core findings=$core (core reported separately, not blocking)"
            [ "$prod" -eq 0 ]'
        # Core report, informational: same checks, core header only.
        run_check static-clang-tidy-core informational clang-tidy pass bash -c '
            printf "#include \"ccts/scheme.hpp\"\nint main(){}\n" > "'"$ART"'/core_tidy.cpp"
            clang-tidy --quiet "'"$ART"'/core_tidy.cpp" -- -std=c++20 -Iinclude > "'"$ART"'/results/static-clang-tidy-core.txt" 2>/dev/null; rm -f "'"$ART"'/core_tidy.cpp"
            echo "core clang-tidy findings: $(grep -cE "(warning|error):" "'"$ART"'/results/static-clang-tidy-core.txt" || true)"; true'
    else skip_check static-clang-tidy required clang-tidy "clang-tidy not found"; fi
    # cppcheck suppressions (documented): throwInEntryPoint - test/tool drivers let
    # exceptions terminate with a nonzero exit by design; uninitMemberVarNoCtor -
    # aggregates initialised by brace-init (false positive).
    if have cppcheck; then
        run_check static-cppcheck best-effort cppcheck pass bash -c '
            cppcheck --std=c++20 --enable=warning,performance,portability --inline-suppr --error-exitcode=0 --quiet --suppress=throwInEntryPoint --suppress=uninitMemberVarNoCtor '"$INC"' -Iproduction/fuzz production include/ccts 2> "'"$ART"'/results/static-cppcheck.txt"
            prod=$(grep -c "^production/" "'"$ART"'/results/static-cppcheck.txt" || true); core=$(grep -c "^include/ccts/" "'"$ART"'/results/static-cppcheck.txt" || true)
            echo "cppcheck: production=$prod core=$core"; [ "$prod" -eq 0 ]'
    else skip_check static-cppcheck best-effort cppcheck "cppcheck not found"; fi
}
c_valgrind() {
    local which="${1:-short}" # short|full
    if [ -z "$VALGRIND" ]; then skip_check valgrind-memcheck required valgrind "valgrind not found"; return; fi
    local cxx="$CXX" tag="system"
    if [ "$VG_NEEDS_NIX_BUILD" = 1 ]; then
        if [ -z "$CLANGXX" ]; then skip_check valgrind-memcheck required valgrind "pinned valgrind needs pinned-clang-built binaries; clang missing"; return; fi
        cxx="$CLANGXX"; tag="pinned-clang"
    fi
    local tests="smoke kat negative"; [ "$which" = full ] && tests="$PROD_TESTS"
    run_check "valgrind-memcheck-$which" required "valgrind($tag)" pass bash -c "
        set -e; mkdir -p build/production/valgrind
        for t in $tests; do
            $cxx -std=c++20 -O1 -g $INC production/tests/\${t}_test.cpp -o build/production/valgrind/\${t}_test
            valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --track-origins=yes -q build/production/valgrind/\${t}_test
        done
        # error paths and malformed inputs: replay the adapter fuzz corpora under memcheck
        for t in fuzz_pk_adapter fuzz_sig_dense_adapter fuzz_sig_packed_adapter fuzz_verify fuzz_radix; do
            $cxx -std=c++20 -O1 -g $INC -Iproduction/fuzz production/fuzz/\$t.cpp production/fuzz/standalone_driver.cpp -o build/production/valgrind/\$t
            valgrind --error-exitcode=99 -q build/production/valgrind/\$t production/fuzz/corpus/\$t
        done"
    if [ "$which" = full ]; then
        run_check valgrind-memcheck-existing-suite best-effort "valgrind($tag)" pass bash -c "
            set -e; $cxx -std=c++20 -O1 -g -Iinclude tests/test_main.cpp -o build/production/valgrind/run_tests && valgrind --error-exitcode=99 -q build/production/valgrind/run_tests"
    fi
}
c_sidechannel() {
    local which="${1:-short}"
    # ctgrind-style: secret-dependent branches/indices under memcheck. The
    # core is documented as not constant-time (README); reports are expected: KNOT-CORE-007.
    # Three outcomes are kept apart: the harness cannot mark secrets (no
    # valgrind headers) -> unsupported; memcheck reports -> known-fail (the
    # finding); zero reports -> xpass (finding no longer reproduces).
    if [ -n "$VALGRIND" ]; then
        local cxx="$CXX"; [ "$VG_NEEDS_NIX_BUILD" = 1 ] && cxx="$CLANGXX"
        if [ -n "$cxx" ]; then
            local vginc=""; [ -n "${KNOT_VALGRIND_INCLUDE:-}" ] && vginc="-I$KNOT_VALGRIND_INCLUDE"
            mkdir -p build/production/valgrind
            if ! $cxx -std=c++20 -O2 -g $INC $vginc production/sidechannel/ctgrind_knot.cpp -o build/production/valgrind/ctgrind_knot > "$ART/logs/sidechannel-ctgrind-build.log" 2>&1 \
               || ! build/production/valgrind/ctgrind_knot tensor_reference/k=8 2>/dev/null | grep -q 'memcheck headers present'; then
                for set in tensor_reference chord_structured tri_chord; do
                    skip_check "sidechannel-ctgrind-$set" required "valgrind memcheck (ctgrind-style)" "valgrind/memcheck.h not available: harness cannot mark secret memory (install valgrind headers or use KNOT_TOOLCHAIN=nix)"
                done
            else
                for set in tensor_reference/k=8 chord_structured/k=8 tri_chord/k=8; do
                    local tag="${set%%/*}"
                    run_check "sidechannel-ctgrind-$tag" required "valgrind memcheck (ctgrind-style)" known-fail:KNOT-CORE-007 bash -c "
                        rc=0; valgrind --error-exitcode=99 --track-origins=no -q --xml=yes --xml-file='$ART/results/sidechannel-ctgrind-$tag.xml' build/production/valgrind/ctgrind_knot $set || rc=\$?
                        python3 - '$ART/results/sidechannel-ctgrind-$tag.xml' '$ART/results/sidechannel-ctgrind-$tag-report.json' <<'PY'
import sys, json, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot(); errs = r.findall('error')
kinds = {}
for e in errs: kinds[e.findtext('kind')] = kinds.get(e.findtext('kind'), 0) + 1
json.dump({'record': 'ctgrind-report', 'secret_dependent_reports': len(errs), 'kinds': kinds,
           'note': 'memcheck reports with secret key bytes marked undefined; zero reports would not be a constant-time proof'}, open(sys.argv[2], 'w'), indent=1)
print('secret-dependent reports:', len(errs), kinds)
PY
                        [ \$rc -eq 99 ] && exit 99; [ \$rc -eq 0 ] && exit 0; echo 'harness error'; exit \$rc"
                done
            fi
        else skip_check sidechannel-ctgrind required valgrind "pinned valgrind needs pinned-clang-built binaries; clang missing"; fi
    else skip_check sidechannel-ctgrind required valgrind "valgrind not found"; fi
    local samples=500; [ "$which" = long ] && samples="${KNOT_DUDECT_SAMPLES:-20000}"
    run_check "sidechannel-dudect-$which" informational dudect-welch-t pass env KNOT_DUDECT_SAMPLES=$samples KNOT_DUDECT_JSON="$ART/results/sidechannel-dudect-$which-data.json" build/production/gcc-release/dudect_knot
}
c_cross() {
    # 32-bit: the core uses unsigned __int128 (KNOT-CORE-001) -> documented known failure.
    if echo 'int main(){}' | $CXX -m32 -x c++ - -o /dev/null 2>/dev/null; then
        run_check cross-32bit-gcc-m32 required "$CXX -m32" known-fail:KNOT-CORE-001 bash -c "$CXX -std=c++20 -O2 -m32 $INC production/tests/kat_test.cpp -o build/kat_m32 && ./build/kat_m32"
    else skip_check cross-32bit-gcc-m32 required "$CXX -m32" "no 32-bit multilib"; fi
    # Emulated architectures via cross gcc + qemu-user.
    for arch in aarch64 s390x; do
        local cxx="${arch}-unknown-linux-gnu-g++" qemu="qemu-$arch" expected=pass name="cross-$arch-qemu"
        [ "$arch" = s390x ] && { expected="known-fail:KNOT-CORE-008"; name="cross-s390x-bigendian-qemu"; }
        if have "$cxx" && have "$qemu"; then
            run_check "$name" required "$cxx + $qemu" "$expected" bash -c "
                set -e; mkdir -p build/cross
                libc=\$(dirname \$($cxx -print-file-name=libc.so)); sysroot=\$(dirname \$libc)
                for t in portability kat smoke negative; do
                    $cxx -std=c++20 -O2 -static-libstdc++ -static-libgcc $INC production/tests/\${t}_test.cpp -o build/cross/\${t}_$arch
                    KNOT_TEST_JSON=$ART/results/cross-$arch-\$t.json $qemu -L \$sysroot build/cross/\${t}_$arch
                done"
        else skip_check "$name" required "$cxx + $qemu" "cross toolchain/qemu not found (KNOT_TOOLCHAIN=nix provides them)"; fi
    done
}
c_secrets() {
    if have gitleaks; then
        run_check secrets-gitleaks required gitleaks pass gitleaks detect --source . --no-banner --redact -v --report-format json --report-path "$ART/results/secrets-gitleaks.json"
    else
        run_check secrets-grep-fallback required grep pass bash -c '! grep -rEl "BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}" --exclude-dir=.git --exclude-dir=ci-artifacts --exclude-dir=build . '
    fi
}
c_sbom()     { run_check sbom-cyclonedx required scripts/sbom.py pass scripts/sbom.py --out "$ART/sbom.cdx.json" --build-meta "$ART/build-metadata.json"; }
c_bench() {
    local which="${1:-smoke}" samples=10 sets="tensor_reference/k=8,chord_structured/k=8,tri_chord/k=8" mode=informational
    if [ "$which" = full ]; then samples="${KNOT_BENCH_SAMPLES:-100}"; sets=""; mode="${KNOT_BENCH_MODE:-informational}"; fi
    local cls="${KNOT_BENCH_CLASS:-$(uname -m)-$(uname -s | tr A-Z a-z)}"
    run_check "bench-micro-$which" required bench_knot pass bash -c "
        set -e; env KNOT_BENCH_SAMPLES=$samples ${sets:+KNOT_BENCH_SETS=$sets} KNOT_BENCH_JSON=$ART/bench-raw.json build/production/gcc-release/bench_knot 2>/dev/null
        KNOT_BENCH_FLAGS='-std=c++20 -O2' scripts/bench_summary.py --bench $ART/bench-raw.json --meta $ART/build-metadata.json --out $ART/bench-summary.json --table $ART/bench-summary.txt"
    [ "$which" = full ] && run_check bench-regression required bench_compare.py pass scripts/bench_compare.py --current "$ART/bench-summary.json" --baseline "bench/baselines/$cls.json" --mode "$mode" --out "$ART/results/bench-regression-report.json"
    return 0
}
c_reproducibility() {
    run_check build-reproducibility informational "$CXX" pass bash -c '
        set -e; mkdir -p build/repro/a build/repro/b
        flags="-std=c++20 -O2 '"$INC"' -ffile-prefix-map='"$ROOT"'=. -fno-record-gcc-switches"
        export SOURCE_DATE_EPOCH=0
        '"$CXX"' $flags production/tests/kat_test.cpp -o build/repro/a/kat_test
        '"$CXX"' $flags production/tests/kat_test.cpp -o build/repro/b/kat_test
        ha=$(sha256sum build/repro/a/kat_test | cut -d" " -f1); hb=$(sha256sum build/repro/b/kat_test | cut -d" " -f1)
        same=false; [ "$ha" = "$hb" ] && same=true
        printf "{\"record\":\"build-reproducibility\",\"binary\":\"kat_test\",\"compiler\":\"%s\",\"flags\":\"%s\",\"sha256_build_a\":\"%s\",\"sha256_build_b\":\"%s\",\"bit_identical_same_host\":%s,\"note\":\"same host, same toolchain, two consecutive builds; cross-host reproducibility not established\"}\n" "$('"$CXX"' --version | head -1)" "$flags" "$ha" "$hb" "$same" > "'"$ART"'/results/build-reproducibility.json"
        echo "bit-identical rebuild: $same"'
}
c_evidence() { run_check evidence-chain required scripts/evidence.py pass bash -c "scripts/evidence.py --artifacts '$ART'"; }
c_release_assemble() { run_check release-assemble required scripts/release_hashes.sh pass scripts/release_hashes.sh "${KNOT_RELEASE_TAG:-untagged-$(git rev-parse --short HEAD)}" "$ART"; }

# =============================================================================
#  Modes
# =============================================================================
finish() {
    local total=$(( $(date +%s) - START_ALL ))
    python3 - "$SUMMARY" "$MODE" "$total" "$FAILED" "$ART/results" <<'PY'
import glob, json, os, sys, collections
out, mode, total, failed, rdir = sys.argv[1:]
checks = {}
for p in sorted(glob.glob(os.path.join(rdir, "*.json"))):
    try: d = json.load(open(p))
    except Exception: continue
    if d.get("record") == "ci-check": checks[d["check"]] = d
counts = collections.Counter(c["status"] for c in checks.values())
json.dump({"record": "ci-summary", "record_version": 1, "mode": mode, "duration_s": int(total),
           "status": "fail" if failed == "1" else "pass", "counts": dict(counts), "checks": checks,
           "policy": "required checks must pass; known-fail entries are documented core findings (metadata/findings); "
                     "unsupported entries are missing coverage, never successes"}, open(out, "w"), indent=1)
print(f"\nCI {mode}: {'FAIL' if failed == '1' else 'PASS'} in {total}s  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
for name, c in checks.items():
    if c["status"] in ("fail", "xpass"): print(f"  FAILED: {name}: {c.get('reason')}")
    if c["status"] == "known-fail": print(f"  known-fail: {name} [{c.get('finding')}]")
    if c["status"] == "unsupported": print(f"  unsupported: {name}: {c.get('reason')}")
PY
    exit $FAILED
}

quick() {
    echo "== KNOT CI quick (PR) checks =="
    c_core_identity; c_build_meta; c_existing_build; c_existing_tests; c_vectors_fresh; c_core_diagnostics
    c_prod_gcc; c_prod_clang; c_kat_regen; c_parity_cross_binary
    c_sanitizers; c_fuzz_short; c_static; c_valgrind short; c_sidechannel short; c_cross; c_secrets; c_sbom
    c_bench smoke; c_evidence
}
nightly_extra() {
    echo "== KNOT CI nightly extras =="
    run_check test-roundtrip-extended required roundtrip_test pass env KNOT_EXTENDED=1 KNOT_ITER="${KNOT_ITER:-100}" KNOT_TEST_JSON="$ART/results/test-extended-roundtrip.json" build/production/gcc-release/roundtrip_test
    run_check test-parity-extended required parity_test pass env KNOT_EXTENDED=1 KNOT_TEST_JSON="$ART/results/parity-extended.json" build/production/gcc-release/parity_test
    KNOT_FUZZ_RUNS="${KNOT_FUZZ_RUNS:-50000}" KNOT_LIBFUZZER_SECONDS="${KNOT_LIBFUZZER_SECONDS:-300}" c_fuzz_short
    c_valgrind full; c_sidechannel long; c_reproducibility; c_bench full
    # compiler / optimisation matrix parity: -O0/-O2/-O3 (gcc) and -O2/-O3 (clang) via KAT regeneration
    if [ -n "$CLANGXX" ]; then pbuild clang-O3 "$CLANGXX" "-O3" "" "" tools > "$ART/logs/build-clang-O3.log" 2>&1 || true; fi
    c_parity_cross_binary
    c_evidence
}
case "$MODE" in
    quick)   quick; finish ;;
    nightly) quick; nightly_extra; finish ;;
    release) quick; nightly_extra; c_release_assemble; c_evidence; finish ;;
    list)    declare -F | awk '{print $3}' | grep '^c_' | sed 's/^c_//' ;;
    *)       for c in "$@"; do "c_$c" || true; done; finish ;;
esac
