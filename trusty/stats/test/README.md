# Development Notes

*    First get [repo_pull.py and gerrit.py](https://android.googlesource.com/platform/development/+/main/tools/repo_pull/) from aosp.

*    Although this repo is not currently in Trusty’s manifest, it’s sufficient to copy these two python scripts to the root of the Trusty project and run them from there. Make sure to follow the [repo_pull installation](https://android.googlesource.com/platform/development/+/main/tools/repo_pull/#installation) steps if necessary.

## Build

Build Android:

```sh
source build/envsetup.sh
lunch qemu_trusty_arm64-userdebug
m
```

Build Trusty:

```sh
./trusty/vendor/google/aosp/scripts/build.py qemu-generic-arm64-test-debug --skip-tests 2>stderr.log
```

## Trusty PORT_TEST

On QEmu:

```sh
./build-root/build-qemu-generic-arm64-test-debug/run --headless --boot-test "com.android.trusty.stats.test" --verbose
```

On device: (Build for your device's debug target on both Adroid and Trusty)

```sh
/vendor/bin/trusty-ut-ctrl -D /dev/trusty-ipc-dev0 "com.android.trusty.stats.test"
```

On device, in a loop:

```sh
cat << 'EOF' > metrics.sh
#!/system/bin/sh
TIMES=${1:-0}
X=0
while [ "$TIMES" -eq 0 -o "$TIMES" -gt "$X" ]
do
  echo "######################## stats.test $X " $(( X++ ));
  /vendor/bin/trusty-ut-ctrl -D /dev/trusty-ipc-dev0 "com.android.trusty.stats.test"
done
EOF

adb wait-for-device
adb push metrics.sh /data/user/test/metrics.sh
adb shell sh /data/user/test/metrics.sh
```

## Android Native Test

On QEmu:

```sh
./build-root/build-qemu-generic-arm64-test-debug/run --headless --android $ANDROID_PROJECT_ROOT --shell-command "/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test" --verbose
```

On device: (Build for your device's debug target on both Adroid and Trusty)

```sh
/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test
```

On device, in a loop:

```sh
cat << 'EOF' > metrics-nw.sh
#!/system/bin/sh
TIMES=${1:-0}
X=0
while [ "$TIMES" -eq 0 -o "$TIMES" -gt "$X" ]
do
  echo "######################## stats.test $X " $(( X++ ));
  /data/nativetest64/vendor/trusty_stats_test/trusty_stats_test
done
EOF

adb wait-for-device
adb push metrics.sh /data/user/test/metrics-nw.sh
adb shell sh /data/user/test/metrics-nw.sh
```

## Trusty Backtrace analysis


```
$ export A2L=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-addr2line
$ export OD=./prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-objdump
$ $OD -d -C build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf > objdump.lst
$ $A2L -e build-root/build-qemu-generic-arm64-test-debug/user_tasks/trusty/user/base/app/metrics/metrics.syms.elf 0xe5104
```
