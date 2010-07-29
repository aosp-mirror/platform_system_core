#!/system/bin/sh

ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2 dev eth0

qemud=`getprop ro.kernel.android.qemud`
case "$qemud" in
    "")
    radio_ril=`getprop ro.kernel.android.ril`
    case "$radio_ril" in
        "")
        # no need for the radio interface daemon
        # telephony is entirely emulated in Java
        setprop ro.radio.noril yes
        stop ril-daemon
        ;;
    esac
    ;;
esac

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

# set up the second interface (for inter-emulator connections)
# if required
my_ip=`getprop net.shared_net_ip`
case "$my_ip" in
    "")
    ;;
    *) ifconfig eth1 "$my_ip" netmask 255.255.255.0 up
    ;;
esac
