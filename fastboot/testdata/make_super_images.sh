#!/bin/bash

set -e
set -x

lpmake \
    --device-size=auto \
    --metadata-size=4096 \
    --metadata-slots=3 \
    --partition=system_a:readonly:0 \
    --alignment=16384 \
    --output=super_empty.img

lpmake \
    --device-size=auto \
    --metadata-size=4096 \
    --metadata-slots=3 \
    --partition=system_a:readonly:0 \
    --alignment=16384 \
    --output=super.img \
    --image=system_a=system.img
