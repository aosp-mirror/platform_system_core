#!/system/bin/sh

ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2 dev eth0

qemud=`getprop.ro.kernel.android.qemud`
if test -z "$qemud"; then
    radio_ril=`getprop ro.kernel.android.ril`
    if test -z "$radio_ril"; then
        # no need for the radio interface daemon
        # telephony is entirely emulated in Java
        setprop ro.radio.noril yes
        stop ril-daemon
    fi
fi

num_dns=`getprop ro.kernel.android.ndns`
case "$num_dns" in
    2) setprop net.eth0.dns2 10.0.2.4
    ;;
    3) setprop net.eth0.dns2 10.0.2.4
    setprop net.eth0.dns3 10.0.2.5
    ;;
    4) setprop net.eth0.dns2 10.0.2.4
    setprop net.eth0.dns3 10.0.2.5
    setprop net.eth0.dns4 10.0.2.6
    ;;
esac

# disable boot animation for a faster boot sequence when needed
boot_anim=`getprop ro.kernel.android.bootanim`
case "$boot_anim" in
    0)  setprop debug.sf.nobootanimation 1
    ;;
esac

# call 'qemu-props' to set system properties from the emulator.
#
/system/bin/qemu-props

# this line doesn't really do anything useful. however without it the
# previous setprop doesn't seem to apply for some really odd reason
setprop ro.qemu.init.completed 1
