# Proxmox VE 9 Build Environment Container Dockerfile
# https://git.proxmox.com/?p=pve-common.git;a=blob_plain;f=README.dev;hb=HEAD
#
# Build:
# docker build -t pve-devbox .

FROM debian:13

ARG DEBIAN_FRONTEND=noninteractive

RUN <<EOF
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

RUN <<EOF
curl -L https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg \
    -o /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF

COPY <<EOF /etc/apt/sources.list.d/proxmox-devel.sources
Types: deb
URIs: http://download.proxmox.com/debian/devel/
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: true
EOF

COPY <<EOF /etc/apt/sources.list.d/proxmox-test.sources
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-test
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: true
EOF

# Block unneeded packages in container
COPY <<EOF /etc/apt/preferences.d/99-unneeded-packages
Package: proxmox-default-kernel proxmox-kernel-* pve-firmware
Pin: release *
Pin-Priority: -1
EOF

RUN <<EOF
apt-get update
apt-get install -y \
    git \
    devscripts \
    build-essential \
    debhelper \
    pve-doc-generator
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF
