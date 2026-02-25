# pve-qemu-builder

Build tooling for compiling [Proxmox VE's pve-qemu](https://github.com/proxmox/pve-qemu) with VM fingerprint suppression patches applied.

## What it does

1. Clones `proxmox/pve-qemu` at a given branch
2. Applies `scripts/anti-detection.sh` — patches QEMU source to suppress common hypervisor fingerprints
3. Builds and outputs a `pve-qemu-kvm_*_amd64.deb` package

## Anti-detection patches

The script addresses fingerprint vectors across several categories:

| ID | Target |
|----|--------|
| H3–H6 | CPUID vendor strings, ACPI OEM IDs, FADT hypervisor identity |
| H7 | SMBIOS manufacturer default |
| M1–M4 | IDE / ATAPI / SCSI / UFS drive vendor and model strings |
| M5 | NVMe controller model and firmware revision |
| M6–M8 | USB vendor IDs and product/manufacturer strings |
| M9 | HDA audio codec vendor ID |
| M12–M13 | SMBIOS cache handles, memory type, and voltage fields |

> Some patches (H1, H2, H8, H10, H11, M10, M11) are commented out by default — see the script for rationale.

## Usage

### Build pve-qemu locally

```bash
bash scripts/build-pve-qemu.sh [branch]
# e.g.
bash scripts/build-pve-qemu.sh master
```

Output `.deb` is written to `./output/`.

### GitHub Actions

**Build pve-qemu** (`workflow_dispatch`):
- Go to Actions → *Build pve-qemu* → Run workflow
- Specify a branch (default: `master`) and an optional release tag

## Requirements

- Docker
