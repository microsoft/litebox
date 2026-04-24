#!/bin/bash
# VS Code Server fix cycle — build, test, report.
#
# Usage:
#   bash litebox_tool_executor/scripts/vscode-fix-cycle.sh [--native-only] [--litebox-only]
#
# This script encodes the development cycle:
#   1. Build all binaries (PIE + non-PIE) and Docker images
#   2. Run native baseline in Docker — must be 0 FAIL
#   3. Run litebox pass in Docker — observe failures
#   4. Report delta for the developer/agent to fix
#
# After fixing a litebox bug, re-run this script to verify.

set -e
cd "$(dirname "$0")/../.."

NATIVE_ONLY=false
LITEBOX_ONLY=false
for arg in "$@"; do
    case $arg in
        --native-only) NATIVE_ONLY=true ;;
        --litebox-only) LITEBOX_ONLY=true ;;
    esac
done

echo "=== Step 1: Build all binaries ==="
cargo build -p litebox_tool_executor -p litebox_broker \
  -p litebox_runner_linux_userland -p litebox_test_harness
cargo rustc -p litebox_test_harness --target-dir target/nonpie \
  -- -C link-args=-no-pie

echo "=== Step 2: Build Docker images ==="
docker build --target litebox-test -t litebox-test \
  -f litebox_tool_executor/rootfs/Dockerfile . --quiet
docker build --target litebox-vscode -t litebox-vscode \
  -f litebox_tool_executor/rootfs/Dockerfile . --quiet

DEBUG_DIR="$(pwd)/target/debug"
NONPIE_DIR="$(pwd)/target/nonpie/debug"

if [ "$LITEBOX_ONLY" = false ]; then
    echo ""
    echo "=== Step 3: Native Baseline (litebox-vscode image) ==="
    docker run --rm --cap-add SYS_PTRACE \
      -v "$DEBUG_DIR:/opt/litebox:ro" \
      -v "$NONPIE_DIR:/opt/nonpie:ro" \
      litebox-vscode /opt/litebox/litebox_test_harness spawn-tree 2>/dev/null \
      | tee /tmp/litebox-native.jsonl \
      | grep -E "SUMMARY"
    echo ""

    NATIVE_FAILS=$(grep '"result":"FAIL"' /tmp/litebox-native.jsonl | wc -l)
    if [ "$NATIVE_FAILS" -gt 0 ]; then
        echo "!!! NATIVE BASELINE HAS $NATIVE_FAILS FAILURES — fix these first:"
        grep '"result":"FAIL"' /tmp/litebox-native.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    print(f'  {r[\"test\"]} [{r[\"agent\"]}]: {r[\"detail\"][:100]}')
"
        if [ "$NATIVE_ONLY" = true ]; then exit 1; fi
    else
        echo "Native baseline: CLEAN (0 FAIL)"
    fi
fi

if [ "$NATIVE_ONLY" = true ]; then
    exit 0
fi

echo ""
echo "=== Step 4: Litebox Pass (litebox-vscode image) ==="
docker run --rm --cap-add SYS_PTRACE \
  -v "$DEBUG_DIR:/opt/litebox:ro" \
  -v "$NONPIE_DIR:/opt/nonpie:ro" \
  litebox-vscode /opt/litebox/litebox_tool_executor \
    --rootfs / --record-baseline -- \
    /opt/litebox/litebox_test_harness spawn-tree 2>/dev/null \
  | tee /tmp/litebox-litebox.jsonl \
  | grep -E "SUMMARY"
echo ""

# Report failures
FAIL_COUNT=$(grep '"result":"FAIL"' /tmp/litebox-litebox.jsonl | wc -l)
XFAIL_COUNT=$(grep '"result":"xfail"' /tmp/litebox-litebox.jsonl | wc -l)
PASS_COUNT=$(grep '"result":"pass"' /tmp/litebox-litebox.jsonl | wc -l)

echo "=== Results ==="
echo "  PASS:  $PASS_COUNT"
echo "  FAIL:  $FAIL_COUNT"
echo "  xfail: $XFAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "=== Litebox Failures (fix these) ==="
    # Group by category prefix
    grep '"result":"FAIL"' /tmp/litebox-litebox.jsonl | python3 -c "
import sys, json, collections
cats = collections.Counter()
for line in sys.stdin:
    r = json.loads(line)
    test = r['test']
    cat = test.split('.')[0]
    cats[cat] += 1
    detail = r['detail'][:120].replace('\n', ' ')
    print(f'  {test} [{r[\"agent\"]}]: {detail}')
print()
print('By category:')
for cat, count in sorted(cats.items()):
    print(f'  {cat}: {count} failures')
"
    echo ""
    echo "=== VSI bootstrap result ==="
    grep '"test":"VSI.bootstrap"' /tmp/litebox-litebox.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    print(f'  Result: {r[\"result\"]}')
    for part in r['detail'].split('\\\\n'):
        print(f'    {part}')
" 2>/dev/null || echo "  (VSI.bootstrap not found in results)"
fi
