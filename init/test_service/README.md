# Sample service for testing
This is a sample service that can be used for testing init.

## Design
The service includes a `.rc` file that allows starting it from init.

    service test_service /system/bin/test_service CapAmb 0000000000003000
        class main
        user system
        group system
        capabilities NET_ADMIN NET_RAW
        disabled
        oneshot

The service accepts any even number of arguments on the command line
(i.e. any number of pairs of arguments.)
It will attempt to find the first element of each pair of arguments in
`/proc/self/status`, and attempt to exactly match the second element of the pair
to the relevant line of `proc/self/status`.

### Example
In the above case, the service will look for lines containing `CapAmb`:

    cat /proc/self/status
    ...
    CapAmb:	0000000000003000

And then attempt to exactly match the token after `:`, `0000000000003000`,
with the command-line argument.
If they match, the service exits successfully. If not, the service will exit
with an error.

## Usage
	mmma -j <jobs> system/core/init/testservice
	adb root
	adb remount
	adb sync
	adb reboot
	adb root
	adb shell start test_service
	adb logcat -b all -d | grep test_service

Look for an exit status of 0.
