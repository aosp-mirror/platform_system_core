# Fuzzers for libinit

## Table of contents
+ [init_parser_fuzzer](#InitParser)
+ [init_property_fuzzer](#InitProperty)
+ [init_ueventHandler_fuzzer](#InitUeventHandler)

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

# <a name="InitProperty"></a> Fuzzer for InitProperty

InitProperty supports the following parameters:
  PropertyType (parameter name: "PropertyType")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`PropertyType`| 0.`STRING`,<br/> 1.`BOOL`,<br/> 2.`INT`,<br/> 3.`UINT`,<br/> 4.`DOUBLE`,<br/> 5.`SIZE`,<br/>6.`ENUM`,<br/>7.`RANDOM`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) init_property_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/init_property_fuzzer/init_property_fuzzer
```

# <a name="InitUeventHandler"></a> Fuzzer for InitUeventHandler

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

InitUeventHandler supports the following parameters:
1. Major (parameter name: `major`)
2. Minor (parameter name: `minor`)
3. PartitionNum (parameter name: `partition_num`)
4. Uid (parameter name: `uid`)
5. Gid (parameter name: `gid`)
6. Action (parameter name: `action`)
7. Path (parameter name: `path`)
8. Subsystem (parameter name: `subsystem`)
9. PartitionName (parameter name: `partition_name`)
10. DeviceName (parameter name: `device_name`)
11. Modalias (parameter name: `modalias`)
12. DevPath (parameter name: `devPath`)
13. HandlerPath (parameter name: `handlerPath`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `major` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `minor` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `partition_num ` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `uid` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `gid` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `action` | `String` | Value obtained from FuzzedDataProvider|
| `path` | `String` | Value obtained from FuzzedDataProvider|
| `subsystem` | `String` | Value obtained from FuzzedDataProvider|
| `partition_name` | `String` | Value obtained from FuzzedDataProvider|
| `device_name` | `String` | Value obtained from FuzzedDataProvider|
| `modalias` | `String` | Value obtained from FuzzedDataProvider|
| `devPath` | `String` | Value obtained from FuzzedDataProvider|
| `handlerPath` | `String` | Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

#### Steps to run
1. Build the fuzzer
```
$ mm -j$(nproc) init_ueventHandler_fuzzer
```
2. Run on device
```
$ adb sync data
$ adb shell /data/fuzz/arm64/init_ueventHandler_fuzzer/init_ueventHandler_fuzzer
```
