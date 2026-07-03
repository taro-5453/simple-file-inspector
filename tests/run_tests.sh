#!/bin/sh
# File Inspector test/demo cases.
#
# Covers the three required categories and a few extras:
#   normal input   - T1 clean text file
#   invalid input  - T2 missing file, T3 unknown option, T4 --hashlist
#                    pointing at a missing list
#   edge cases     - T5 empty file, T6 renamed executable (mismatch),
#                    T7 high-entropy blob, T8 IOC extraction,
#                    T9 hash-list match, T10 SHA-256 vs system tool
#
# Each case runs the real binary and checks BOTH the exit code and a
# pattern in the output. Exits non-zero if any case fails.
set -u
cd "$(dirname "$0")/.."

echo "Building..."
make >/dev/null
sh examples/generate.sh >/dev/null

pass=0
fail=0

# run_case <name> <expected-exit> <required-output-pattern> <cmd...>
run_case() {
    name=$1; want=$2; pattern=$3; shift 3
    out=$("$@" 2>&1); got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL  $name (exit $got, expected $want)"
        fail=$((fail + 1))
    elif ! printf '%s\n' "$out" | grep -q "$pattern"; then
        echo "FAIL  $name (output missing: $pattern)"
        fail=$((fail + 1))
    else
        echo "PASS  $name"
        pass=$((pass + 1))
    fi
}

# --- normal input ---
run_case "T1 clean text file"        0 "Verdict: CLEAN" \
    ./fileinspect examples/normal.txt

# --- invalid input ---
run_case "T2 missing file"           1 "cannot open" \
    ./fileinspect does-not-exist.bin
run_case "T3 unknown option"         1 "unknown option" \
    ./fileinspect --frobnicate examples/normal.txt
run_case "T4 missing hash list"      1 "cannot open hash list" \
    ./fileinspect --hashlist no-such-list.txt examples/normal.txt

# --- edge cases ---
run_case "T5 empty file"             0 "Empty file" \
    ./fileinspect examples/empty.bin
run_case "T6 renamed executable"     0 "Extension mismatch" \
    ./fileinspect examples/renamed-executable.jpg
run_case "T7 high entropy"           0 "High entropy" \
    ./fileinspect examples/high-entropy.bin
run_case "T8 IOC extraction"         0 "2 IPv4 address(es), 2 URL(s)" \
    ./fileinspect examples/iocs.txt
run_case "T9 hash-list match"        0 "MATCH - known-bad hash" \
    ./fileinspect --hashlist examples/demo-hashlist.txt examples/renamed-executable.jpg

# --- T10: our SHA-256 must equal the system tool's ---
if command -v shasum >/dev/null 2>&1; then
    ours=$(./fileinspect examples/normal.txt | grep 'SHA-256' | awk '{print $2}')
    theirs=$(shasum -a 256 examples/normal.txt | awk '{print $1}')
    if [ "$ours" = "$theirs" ]; then
        echo "PASS  T10 SHA-256 matches system shasum"
        pass=$((pass + 1))
    else
        echo "FAIL  T10 SHA-256 mismatch (ours $ours vs $theirs)"
        fail=$((fail + 1))
    fi
else
    echo "SKIP  T10 (shasum not available)"
fi

echo
echo "Results: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
