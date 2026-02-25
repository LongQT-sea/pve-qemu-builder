#!/usr/bin/env bash
# https://git.proxmox.com/?p=pve-edk2-firmware.git
set -euo pipefail

BRANCH="${1:-master}"
IMAGE="ghcr.io/longqt-sea/pve-devbox:latest"

docker run --rm --user $(id -u):$(id -g) \
    -v "./output:/output" \
    "$IMAGE" sh -e -c "
    echo 'APT::Get::Assume-Yes true;' > /etc/apt/apt.conf.d/90assumeyes
    apt-get update

    git clone --depth=1 --branch '$BRANCH' \
      git://git.proxmox.com/git/pve-edk2-firmware.git

    cd pve-edk2-firmware && git submodule update --init --recursive
    mk-build-deps --install
    make clean && make deb
    cp /pve-edk2-firmware/pve-edk2-firmware-ovmf_*_all.deb /output/
    chown -R $(id -u):$(id -g) /output
"
