#!/bin/bash

# generate the arch-specific files from the generic one

set -ex

cd "$(dirname "$0")"
CPP='cpp -undef -E -P code_coverage.policy.def'
$CPP -D__arm__ -o code_coverage.arm.policy
$CPP -D__aarch64__ -D__LP64__ -o code_coverage.arm64.policy
$CPP -D__i386__ -o code_coverage.x86.policy
$CPP -D__x86_64__ -D__LP64__ -o code_coverage.x86_64.policy
