ADB_TESTS="adbd_test adb_crypto_test adb_pairing_auth_test adb_pairing_connection_test adb_tls_connection_test"
ADB_TEST_BINARIES=""
for TEST in $ADB_TESTS; do
  ADB_TEST_BINARIES="--object=$ANDROID_PRODUCT_OUT/data/nativetest64/$TEST/$TEST $ADB_TEST_BINARIES"
done
