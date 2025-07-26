#!/bin/bash

SUDO=''
if (( $EUID != 0 )); then
    SUDO='sudo'
fi

curl https://github.com/capstone-engine/capstone/archive/refs/tags/4.0.1.tar.gz -Lo ./capstone.tar.gz \
 && tar -xf capstone.tar.gz && mv ./capstone-* ./capstone \
 && cd capstone \
 && CAPSTONE_ARCHS="aarch64 x86" ./make.sh \
 && $SUDO ./make.sh install
