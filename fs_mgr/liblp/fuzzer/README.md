# Fuzzers for liblp
## Table of contents
+  [liblp_builder_fuzzer](#Builder)
+  [liblp_super_layout_builder_fuzzer](#SuperBuilder)

# <a  name="Builder"></a> Fuzzer for LiblpBuilder

LiblpBuilder supports the following parameters:
1. kAttributeTypes (parameter name: "attribute")
2. blockDevSize (parameter name: "blockdev_size")
3. metadataMaxSize (parameter name: "metadata_max_size")
4. metadataSlotCount (parameter name: "metadata_slot_count")
5. partitionName (parameter name: "partition_name")
6. superBlockDeviceName (parameter name: "block_device_name")
7. blockDeviceInfoSize (parameter name: "block_device_info_size")
8. alignment (parameter name: "alignment")
9. alignmentOffset (parameter name: "alignment_offset")
10. logicalBlockSize (parameter name: "logical_block_size")
11. maxMetadataSize (parameter name: "max_metadata_size")
12. numSlots (parameter name: "metadata_slot_count")
13. deviceIndex (parameter name: "device_index")
14. start (parameter name: "start")
15. end (parameter name: "end")
16. addedGroupName (parameter name: "group_name")
17. partitionGroupName (parameter name: "partition_name")
18. numSectors (parameter name: "num_sectors")
19. physicalSector (parameter name: "physical_sector")
20. resizedPartitionSize (parameter name: "requested_size")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kAttributeTypes`| 1.`LP_PARTITION_ATTR_NONE`,<br/> 2.`LP_PARTITION_ATTR_READONLY`,<br/> 3.`LP_PARTITION_ATTR_SLOT_SUFFIXED`,<br/> 4.`LP_PARTITION_ATTR_UPDATED`,<br/> 5.`LP_PARTITION_ATTR_DISABLED`|Value obtained from FuzzedDataProvider|
|`blockDevSize`| Integer value from `0` to `100000`|Value obtained from FuzzedDataProvider|
|`metadataMaxSize`| Integer value from `0` to `10000` |Value obtained from FuzzedDataProvider|
|`metadataSlotCount`| Integer value from `0` to `2` |Value obtained from FuzzedDataProvider|
|`partitionName`| String |Value obtained from FuzzedDataProvider|
|`superBlockDeviceName`| String |Value obtained from FuzzedDataProvider|
|`blockDeviceInfoSize`| Integer |Value obtained from FuzzedDataProvider|
|`alignment`| Integer |Value obtained from FuzzedDataProvider|
|`alignmentOffset`| Integer |Value obtained from FuzzedDataProvider|
|`logicalBlockSize`| Integer |Value obtained from FuzzedDataProvider|
|`maxMetadataSize`| Integer value from `0` to `10000` |Value obtained from FuzzedDataProvider|
|`numSlots`| Integer value from `0` to `2` |Value obtained from FuzzedDataProvider|
|`deviceIndex`| Integer |Value obtained from FuzzedDataProvider|
|`start`| Integer |Value obtained from FuzzedDataProvider|
|`end`| Integer |Value obtained from FuzzedDataProvider|
|`partitionGroupName`| String |Value obtained from FuzzedDataProvider|
|`numSectors`| Integer value from `1` to `1000000` |Value obtained from FuzzedDataProvider|
|`physicalSector`| Integer value from `1` to `1000000` |Value obtained from FuzzedDataProvider|
|`resizedPartitionSize`| Integer value from `0` to `10000` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) liblp_builder_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/liblp_builder_fuzzer/liblp_builder_fuzzer
```

# <a  name="SuperBuilder"></a> Fuzzer for LiblpSuperLayoutBuilder

SuperLayoutBuilder supports the following parameters:
1. kAttributeTypes (parameter name: "attribute")
2. blockDevSize (parameter name: "blockdev_size")
3. metadataMaxSize (parameter name: "metadata_max_size")
4. metadataSlotCount (parameter name: "metadata_slot_count")
5. partitionName (parameter name: "partition_name")
6. data (parameter name: "data")
7. imageName (parameter name: "image_name")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kAttributeTypes`| 1.`LP_PARTITION_ATTR_NONE`,<br/> 2.`LP_PARTITION_ATTR_READONLY`,<br/> 3.`LP_PARTITION_ATTR_SLOT_SUFFIXED`,<br/> 4.`LP_PARTITION_ATTR_UPDATED`,<br/> 5.`LP_PARTITION_ATTR_DISABLED`|Value obtained from FuzzedDataProvider|
|`blockDevSize`| Integer value from `0` to `100000`|Value obtained from FuzzedDataProvider|
|`metadataMaxSize`| Integer value from `0` to `10000` |Value obtained from FuzzedDataProvider|
|`metadataSlotCount`| Integer value from `0` to `2` |Value obtained from FuzzedDataProvider|
|`partitionName`| String |Value obtained from FuzzedDataProvider|
|`data`| String |Value obtained from FuzzedDataProvider|
|`imageName`| String |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) liblp_super_layout_builder_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/liblp_super_layout_builder_fuzzer/liblp_super_layout_builder_fuzzer
```
