#!/usr/bin/env bash
#
# run_fuzz.sh — fuzzing campaign driver for mini-sec-lab.
#
#   ./run_fuzz.sh           # full: 100,000 iters per component
#   ./run_fuzz.sh smoke     # quick 2,000-iter sanity run
#   ./run_fuzz.sh selftest  # validate the engine on a deliberately
#                           # vulnerable target (crash/timeout/leak)
#
# Exits non-zero if any component campaign records a finding, or if the
# engine self-test fails.
set -euo pipefail
cd "$(dirname "$0")"

MODE=${1:-full}
case "$MODE" in
    smoke) ITERS=2000 ;;
    full)  ITERS=100000 ;;
    selftest) ITERS=4000 ;;
    *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

export UBSAN_OPTIONS="abort_on_error=1:halt_on_error=1:print_stacktrace=1"
export LSAN_OPTIONS="exitcode=23"

COMPONENTS=(reqguard pathguard tokenauth)
RNG_SEED=0x5eed

make --no-print-directory all seeds

# ASan reads ASAN_OPTIONS at process startup; give every invocation a
# log directory the engine can scan to tell leak-aborts from crashes.
# FUZZ_LOG_DIR tells the engine's oneshot path which dir was chosen.
with_asan_logs() {
    local dir=$1; shift
    mkdir -p "$dir"
    ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:halt_on_error=1:symbolize=1:exitcode=23:log_path=$dir/asan" \
    FUZZ_LOG_DIR="$dir" "$@"
}

run_campaign() {
    local name=$1 iters=$2
    echo "=================================================================="
    echo " campaign: $name ($iters iterations, rng_seed=$RNG_SEED)"
    echo "=================================================================="
    with_asan_logs "out/$name/logs" \
        ./fuzz-$name campaign \
        --corpus corpus/$name \
        --out out/$name \
        --iters "$iters" \
        --batch 200 \
        --rng-seed "$RNG_SEED" \
        --timeout-ms 1000
}

if [[ "$MODE" == "selftest" ]]; then
    # The self-test target is supposed to fail; verify that the engine
    # catches all three failure classes and that every minimized sample
    # reproduces standalone.
    echo "== engine self-test (vulnerable dummy target)"
    set +e
    with_asan_logs out/selftest/logs \
        ./fuzz-selftest campaign \
        --corpus corpus/selftest \
        --out out/selftest \
        --iters "$ITERS" --batch 100 --rng-seed "$RNG_SEED" \
        --timeout-ms 800
    rc=$?
    set -e
    [[ $rc -ne 0 ]] || { echo "SELFTEST FAIL: engine reported a clean run on the buggy target"; exit 1; }

    fail=0
    for kind in crash timeout leak; do
        sample=""
        for f in out/selftest/$kind-*.min; do
            [[ -e $f ]] && sample=$f && break
        done
        [[ -n $sample ]] || { echo "SELFTEST FAIL: no $kind finding"; fail=1; continue; }
        echo "-- verifying minimized $kind sample: $sample"
        set +e
        with_asan_logs "/tmp/fuzz-st-$kind-$$" \
            ./fuzz-selftest oneshot --input "$sample" --timeout-ms 800
        orc=$?
        set -e
        rm -rf "/tmp/fuzz-st-$kind-$$"
        case "$kind" in
            crash)   want=70 ;;
            timeout) want=76 ;;
            leak)    want=23 ;;
        esac
        if [[ $orc -ne $want ]]; then
            echo "SELFTEST FAIL: $sample did not reproduce ($orc != $want)"
            fail=1
        fi

        # And the manual minimize subcommand must reproduce the same class.
        with_asan_logs "/tmp/fuzz-st-min-$kind-$$" \
            ./fuzz-selftest minimize \
            --input "${sample%.min}.raw" \
            --output "out/selftest/remin-$kind.bin" \
            --kind "$kind" --timeout-ms 800 >/dev/null
        rm -rf "/tmp/fuzz-st-min-$kind-$$"
    done

    # Determinism: re-running with the same rng seed must yield findings
    # at the same iterations as the first run.
    cp out/selftest/manifest.json out/selftest/manifest.first.json
    set +e
    with_asan_logs out/selftest-rerun/logs \
        ./fuzz-selftest campaign \
        --corpus corpus/selftest \
        --out out/selftest-rerun \
        --iters "$ITERS" --batch 100 --rng-seed "$RNG_SEED" \
        --timeout-ms 800 >/dev/null 2>&1
    set -e
    if ! diff -u <(grep -o '"iteration": [0-9]*' out/selftest/manifest.first.json) \
                 <(grep -o '"iteration": [0-9]*' out/selftest-rerun/manifest.json) >/dev/null; then
        echo "SELFTEST FAIL: rerun with the same rng seed found different iterations"
        fail=1
    fi

    [[ $fail -eq 0 ]] || exit 1
    echo "engine self-test PASSED (crash/timeout/leak found, minimized, reproduced, deterministic)"
fi

# Real components: a clean run means zero crashes, zero timeouts, zero leaks.
overall=0
for c in "${COMPONENTS[@]}"; do
    if ! run_campaign "$c" "$ITERS"; then
        echo "FAIL: $c produced findings — see out/$c/"
        overall=1
    fi
    test -f out/$c/manifest.json && cat out/$c/manifest.json
done

if [[ $overall -eq 0 ]]; then
    echo
    echo "ALL CAMPAIGNS CLEAN: $ITERS iterations x ${#COMPONENTS[@]} components,"
    echo "under ASan/UBSan/LSan, zero crashes / zero timeouts / zero leaks."
fi
exit $overall
