#!/bin/sh

# Script implements watermark_scale calculation which results in the same low
# watermark as if extra_free_kbytes tunable were to be used.
#
# Usage: extra_free_kbytes.sh <extra_free_kbytes value>
#
# extra_free_kbytes is distributed between zones based on
# zone.managed_pages/vm_total_pages ratio, where vm_total_pages is the sum of
# zone.managed_pages for all zones (zone.high used in this calculation is 0
# when this is calculated). Therefore for each zone its share is calculated as:
#
# extra_free_pages = extra_free_kbytes / page_size
# extra_share = extra_free_pages * managed_pages / vm_total_pages
#
# This extra_share is added to the low and high watermarks:
#
# low = min + max(min / 4, managed_pages * (watermark_scale / 10000)) + extra_share
# high = min + 2 * max(min / 4, managed_pages * (watermark_scale / 10000)) + extra_share
#
# Because Android uses extra_free_kbytes to adjust the low watermark, we ignore
# the difference in how watermark_scale and extra_free_kbytes affect the high
# watermark and will match the low watermark only.
#
# To eliminate extra_share and compansate the difference with watermark_scale,
# a new watermark_scale_new is calculated as:
#
# (1) max(min / 4, managed_pages * (watermark_scale / 10000)) + extra_share =
#   max(min / 4, managed_pages * (watermark_scale_new / 10000))
#
# Two cases to consider:
# A. managed_pages * (watermark_scale / 10000) > min / 4
# The formula (1) becomes:
#
# managed_pages * (watermark_scale / 10000) + extra_share =
#   managed_pages * (watermark_scale_new / 10000)
#
# after simplifying and substituting extra_share formula becomes:
#
# (2) watermark_scale_new = watermark_scale + extra_free_pages / vm_total_pages * 10000
#
# B. managed_pages * (watermark_scale / 10000) < min / 4
# The formula (1) becomes:
#
# min / 4 + extra_share = max(min / 4, managed_pages * (watermark_scale_new / 10000))
#
# after calculating watermark_scale_new, if (managed_pages * (watermark_scale_new / 10000))
# is still smaller than min / 4 then we can't compensate extra_share with
# watermark_scale anyway. Therefore calculation becomes:
#
# watermark_scale_new = (min / 4 + extra_share) / managed_pages * 10000
#
# after simplifying and substituting extra_share formula becomes:
#
# (3) watermark_scale_new = (min / 4) * 10000 / managed_pages + extra_free_pages / vm_total_pages * 10000
#
# After defining watermark_delta = extra_free_pages / vm_total_pages * 10000:
#
# if (managed_pages * (watermark_scale / 10000) > min / 4)
#     watermark_scale_new = watermark_scale + watermark_delta
# else
#     watermark_scale_new = (min / 4) * 10000 / managed_pages + watermark_delta
#

if [ "$#" -ne 1 ]
then
    echo "Usage: $0 <extra_free_kbytes value>"
    exit
fi

extra_free_kbytes=$1

# if extra_free_kbytes knob exists, use it and exit
if [ -e /proc/sys/vm/extra_free_kbytes ]
then
    echo $extra_free_kbytes > /proc/sys/vm/extra_free_kbytes
    exit
fi

# record the original watermark_scale_factor value
watermark_scale=$(getprop "ro.kernel.watermark_scale_factor")
if [ -z "$watermark_scale" ]
then
    watermark_scale=$(cat /proc/sys/vm/watermark_scale_factor)
    setprop "ro.kernel.watermark_scale_factor" "$watermark_scale"
    # On older distributions with no policies configured setprop may fail.
    # If that happens, use the kernel default of 10.
    if [ -z $(getprop "ro.kernel.watermark_scale_factor") ]
    then
        watermark_scale=10
    fi
fi

# convert extra_free_kbytes to pages
page_size=$(getconf PAGESIZE)
page_size_kb=$((page_size/1024))
extra_free_pg=$((extra_free_kbytes/page_size_kb))

managed=($(grep managed /proc/zoneinfo | awk '{print $2}'))
length=${#managed[@]}
min=($(grep "min" /proc/zoneinfo | awk '{print $2}'))

# calculate vm_total_pages.
# WARNING: if the final low watermark differs from the original, the source of
# the error is likely vm_total_pages which is impossible to get exact from the
# userspace. Grep for "Total pages" in the kernel logs to see the actual
# vm_total_pages and plug it in the calculation to confirm the source of the
# error. Error caused by this inaccuracy is normally within 1% range.
vm_total_pages=0
i=0
while [ $i -lt $length ]
do
    vm_total_pages=$((vm_total_pages + managed[i]))
    i=$((i+1))
done

# calculate watermark_scale_new for each zone and choose the max
max_watermark_scale=0
i=0
while [ $i -lt $length ]
do
    # skip unmanaged zones
    if [ ${managed[i]} -eq 0 ]
    then
        i=$((i+1))
        continue
    fi

    base_margin=$((min[i] / 4))
    calc_margin=$(echo "${managed[i]} * $watermark_scale / 10000" | bc)
    # round the value by adding 0.5 and truncating the decimal part
    watermark_delta=$(echo "x=($extra_free_pg / ($vm_total_pages / 10000) + 0.5); scale = 0; x/1" | bc -l)
    if [ $calc_margin -gt $base_margin ]
    then
        watermark_scale_new=$(echo "$watermark_scale + $watermark_delta" | bc)
    else
        watermark_scale_new=$(echo "$base_margin / (${managed[i]} / 10000) + $watermark_delta" | bc)
    fi

    if [ $max_watermark_scale -lt $watermark_scale_new ]
    then
        max_watermark_scale=$watermark_scale_new
    fi

    i=$((i+1))
done

echo $max_watermark_scale > /proc/sys/vm/watermark_scale_factor
