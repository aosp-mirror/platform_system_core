#!/bin/sh

# This script adjusts overrides of the memcg v2 MaxActivationDepth value at runtime.
# The override value needs to be accessible starting very early in the Android boot, where aconfig
# flags and system properties do not work. A file on /metadata is used instead.

# The kernel allows this to be as high as 65535, but our Android hierarchy is never that deep.
MAX_ALLOWED_DEPTH=5

# Store overridden MaxActivationDepths here for libprocessgroup to find them
OVERRIDE_FILE_PATH="/metadata/libprocessgroup/memcg_v2_max_activation_depth"

if [ "$#" -ne 1 ]
then
    echo "Usage: $0 <memcg v2 MaxActivationDepth value>"
    exit 99
fi

max_activation_depth=$1

if [[ $max_activation_depth != +([0-9]) ]]
then
    echo "MaxActivationDepth value must be a positive integer: $max_activation_depth"
    exit 98
fi

if [ $max_activation_depth -lt 0 ]
then
    echo "Negative MaxActivationDepth is invalid: $max_activation_depth"
    exit 97
fi

if [ $max_activation_depth -gt $MAX_ALLOWED_DEPTH ]
then
    echo "MaxActivationDepth is too large: $max_activation_depth"
    exit 96
fi

grep memory /sys/fs/cgroup/cgroup.controllers
if [ $? -ne 0 ]
then
    echo "memcg v2 is not available on this device!"
    exit 95
fi

current_activation_depth=$(cat $OVERRIDE_FILE_PATH)
if [ $? -ne 0 ]
then
    # Find the default activation depth in the absence of any properties / overrides.
    #
    # To do this 100% correctly requires JSON parsing which we don't really want to do here.
    # We know that this will be called only for Pixel (for a limited-duration experiment), and that
    # Pixel does not override cgroups.json, therefore we can assume that the system cgroups.json has
    # only a single MaxActivationDepth entry which corresponds to the v2 memory controller. So we
    # can just grep for the default value.
    default_activation_depth=$(grep MaxActivationDepth /system/etc/cgroups.json | tr -dc '0-9')
    if [ $? -ne 0 -o $default_activation_depth -gt $MAX_ALLOWED_DEPTH ]
    then
        # If MaxActivationDepth is not present, libprocessgroup does not limit how deep it will activate
        default_activation_depth=$MAX_ALLOWED_DEPTH
    fi
    current_activation_depth=$default_activation_depth
fi

# libprocessgroup will pick this up for all future cgroup creations, including on the next boot
echo $max_activation_depth > $OVERRIDE_FILE_PATH
chmod ugo+r $OVERRIDE_FILE_PATH

if [ $max_activation_depth -lt $current_activation_depth ]
then
    # We can deactivate memcgs which are deeper than the new depth value, however that would leave
    # behind zombie memcgs which would ruin the metrics produced from this device. The only way to
    # eliminate those zombies is to remove the entire cgroup, which we cannot do without killing
    # all the contained processes. So the only real option we have is to reboot here, but that would
    # look like a random reboot to users. So don't do anything now. Wait until the next reboot for
    # the new setting to be applied.
    :
elif [ $max_activation_depth -gt $current_activation_depth ]
then
    for d in $(seq $max_activation_depth)
    do
        for f in $(find /sys/fs/cgroup/ -mindepth $d -maxdepth $d -name cgroup.subtree_control)
        do
            echo "+memory" > $f
        done
    done
fi
