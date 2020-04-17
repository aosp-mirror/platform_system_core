snapshot\_power\_test
---------------------

snapshot\_power\_test is a standalone test to simulate power failures during a snapshot-merge operation.

### Test Setup

Start by creating two large files that will be used as the pre-merge and post-merge state. You can take two different partition images (for example, a product.img from two separate builds), or just create random data:

	dd if=/dev/urandom of=pre-merge count=1024 bs=1048576
	dd if=/dev/urandom of=post-merge count=1024 bs=1048576

Next, push these files to an unencrypted directory on the device:

	adb push pre-merge /data/local/unencrypted
	adb push post-merge /data/local/unencrypted

Next, run the test setup:

	adb sync data
	adb shell /data/nativetest64/snapshot_power_test/snapshot_power_test \
		/data/local/unencrypted/pre-merge \
		/data/local/unencrypted/post-merge

This will create the necessary fiemap-based images.

### Running
The actual test can be run via `run_power_test.sh`. Its syntax is:

	run_power_test.sh <POST_MERGE_FILE>

`POST_MERGE_FILE` should be the path on the device of the image to validate the merge against. Example:

	run_power_test.sh /data/local/unencrypted/post-merge

The device will begin the merge with a 5% chance of injecting a kernel crash every 10ms. The device should be capable of rebooting normally without user intervention. Once the merge has completed, the test will run a final check command to validate the contents of the snapshot against the post-merge file. It will error if there are any incorrect blocks.

Two environment variables can be passed to `run_power_test.sh`:
1. `FAIL_RATE` - A fraction between 0 and 100 (inclusive) indicating the probability the device should inject a kernel crash every 10ms.
2. `DEVICE_SERIAL` - If multiple devices are attached to adb, this argument is passed as the serial to select (to `adb -s`).
