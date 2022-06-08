# Fuzzers for libinit

## Table of contents
+ [init_parser_fuzzer](#InitParser)

# <a name="InitParser"></a> Fuzzer for InitParser

InitParser supports the following parameters:
1. ValidPathNames (parameter name: "kValidPaths")
2. ValidParseInputs (parameter name: "kValidInputs")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kValidPaths`| 0.`/system/etc/init/hw/init.rc`,<br/> 1.`/system/etc/init` |Value obtained from FuzzedDataProvider|
|`kValidInputs`| 0.`{"","cpu", "10", "10"}`,<br/> 1.`{"","RLIM_CPU", "10", "10"}`,<br/> 2.`{"","12", "unlimited", "10"}`,<br/> 3.`{"","13", "-1", "10"}`,<br/> 4.`{"","14", "10", "unlimited"}`,<br/> 5.`{"","15", "10", "-1"}` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_parser_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_parser_fuzzer/init_parser_fuzzer
```
