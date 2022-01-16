#!/bin/sh
#
# Run host tests
atest --host libfs_avb_test          # Tests public libfs_avb APIs.

# Tests libfs_avb private APIs.
# The tests need more time to finish, so increase the timeout to 5 mins.
# The default timeout is only 60 seconds.
atest --host libfs_avb_internal_test -- --test-arg \
    com.android.tradefed.testtype.HostGTest:native-test-timeout:5m

# Run device tests
atest libfs_avb_device_test          # Test public libfs_avb APIs on a device.
