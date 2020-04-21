#!/bin/bash

set -euxo pipefail

OUTPUT_DIR=$(realpath $(dirname "$0"))
. "$OUTPUT_DIR"/include.sh

rm -rf "$OUTPUT_DIR"/report

cd $ANDROID_BUILD_TOP
llvm-cov show --instr-profile="$OUTPUT_DIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  /proc/self/cwd/system/core/adb \
  $ADB_TEST_BINARIES \
  --show-region-summary=false \
  --format=html -o "$OUTPUT_DIR"/report

llvm-cov report --instr-profile="$OUTPUT_DIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  /proc/self/cwd/system/core/adb \
  $ADB_TEST_BINARIES \
  --show-region-summary=false
