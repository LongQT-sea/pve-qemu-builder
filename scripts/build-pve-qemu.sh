#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:-master}"
IMAGE="ghcr.io/longqt-sea/pve-devbox:latest"

docker run --rm \
    -v "./output:/output" \
    -v "$(pwd)/scripts/anti-detection.sh:/anti-detection.sh:ro" \
    "$IMAGE" sh -c "
    echo 'APT::Get::Assume-Yes true;' > /etc/apt/apt.conf.d/90assumeyes
    apt-get update

    git clone --depth=1 --branch '$BRANCH' \
      https://github.com/proxmox/pve-qemu

    cd pve-qemu && git submodule update --init --recursive
    mk-build-deps --install
    cd qemu && meson subprojects download
    bash /anti-detection.sh && cd ..
    make clean && make deb
    cp /pve-qemu/pve-qemu-kvm_*_amd64.deb /output/
"
