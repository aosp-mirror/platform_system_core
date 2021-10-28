# Fuzzer for libfastboot

## Plugin Design Considerations
The fuzzer plugin for libfastboot is designed based on the understanding of the
source code and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libfastboot supports the following parameters:
1. Year (parameter name: `year`)
2. Month (parameter name: `month`)
3. Day (parameter name: `day`)
4. Version (parameter name: `version`)
5. Fs Option (parameter name: `fsOption`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `year` | `2000` to `2127` | Value obtained from FuzzedDataProvider|
| `month` | `1` to `12` | Value obtained from FuzzedDataProvider|
| `day` | `1` to `31` | Value obtained from FuzzedDataProvider|
| `version` | `0` to `127` | Value obtained from FuzzedDataProvider|
| `fsOption` | 0. `casefold` 1. `projid` 2. `compress` | Value obtained from FuzzedDataProvider|

##### Maximize utilization of input data
The plugin feeds the entire input data to the module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build fastboot_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) fastboot_fuzzer_fuzzer
```
#### Steps to run
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/${TARGET_ARCH}/fastboot_fuzzer/fastboot_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
