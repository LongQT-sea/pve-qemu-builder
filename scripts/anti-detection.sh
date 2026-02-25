#!/usr/bin/env bash
# =============================================================================
# anti-detection.sh -- QEMU VM-fingerprint suppression patch script
#
# Addresses detection vectors identified in the QEMU source audit:
#   H1  CPUID hypervisor presence bit (ECX bit 31)
#   H2  CPUID KVM vendor string "KVMKVMKVM"
#   H3  CPUID TCG vendor string "TCGTCGTCGTCG"
#   H4  CPUID Xen vendor string "XenVMMXenVMM"
#   H5  ACPI OEM ID "BOCHS " / OEM Table ID "BXPC    "
#   H6  ACPI FADT Hypervisor Vendor Identity "QEMU"
#   H7  SMBIOS manufacturer default "QEMU"
#   H8  Firmware config signature "QEMU" / "QEMU CFG"
#   H11 PCI VGA vendor/device 0x1234:0x1111
#   M1  IDE drive model strings "QEMU HARDDISK" / "QEMU DVD-ROM"
#   M2  ATAPI INQUIRY vendor/product "QEMU" / "QEMU DVD-ROM"
#   M3  SCSI vendor "QEMU", products "QEMU HARDDISK" / "QEMU CD-ROM"
#   M4  UFS SCSI INQUIRY vendor "QEMU"
#   M5  NVMe model "QEMU NVMe Ctrl" and firmware revision QEMU_VERSION
#   M6  USB vendor ID 0x46f4 (CRC16 of "QEMU")
#   M7  USB product strings "QEMU USB Hub" / "QEMU USB HARDDRIVE" / etc.
#   M8  USB HID vendor ID 0x0627
#   M9  HDA audio codec vendor ID 0x1af4
#   M10 Hyper-V vendor ID default "Microsoft Hv"
#   M11 SMBIOS BIOS characteristics extension byte VM flag (0x14)
#   M12 SMBIOS processor cache handles 0xFFFF
#   M13 SMBIOS memory type "RAM" (0x07) and zero voltage fields
#
# Usage:
#   cd /path/to/pve-qemu/qemu
#   bash /path/to/anti-detection.sh [--dry-run]
#
# Options:
#   --dry-run   Print what would change without modifying any files
#
# Requirements:
#   - Must be run from inside the QEMU source tree (the qemu/ subdirectory)
#   - GNU sed (Linux), or BSD sed on macOS (auto-detected)
#   - Standard POSIX utilities: grep, awk, uname
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Global state
# -----------------------------------------------------------------------------
SCRIPT_VERSION="1.2.0"
DRY_RUN=false
SED_BIN="sed"

# Counters (incremented by helper functions)
COUNT_APPLIED=0
COUNT_SKIPPED_MISSING=0   # pattern not found in file (version drift)
COUNT_SKIPPED_ALREADY=0   # change already applied (idempotent re-run)
COUNT_ERRORS=0

# Log of every action taken, for the final summary
declare -a APPLIED_LOG=()
declare -a SKIPPED_MISSING_LOG=()
declare -a SKIPPED_ALREADY_LOG=()
declare -a ERROR_LOG=()

# ANSI colour codes (disabled if not a terminal)
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'
    C_RED='\033[0;31m'
    C_CYAN='\033[0;36m'
    C_DIM='\033[2m'
else
    C_RESET='' C_BOLD='' C_GREEN='' C_YELLOW='' C_RED='' C_CYAN='' C_DIM=''
fi

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
log_info()    { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
log_ok()      { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET}   $*"; }
log_error()   { echo -e "${C_RED}[ERROR]${C_RESET}  $*" >&2; }
log_skip()    { echo -e "${C_DIM}[SKIP]${C_RESET}   $*"; }
log_dry()     { echo -e "${C_YELLOW}[DRY]${C_RESET}    $*"; }
log_section() { echo -e "\n${C_BOLD}$* ──${C_RESET}"; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run|-n)
                DRY_RUN=true
                log_warn "Dry-run mode enabled -- no files will be modified"
                ;;
            --help|-h)
                grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
                exit 0
                ;;
            *)
                log_error "Unknown argument: $arg"
                echo "Usage: $0 [--dry-run]" >&2
                exit 1
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Safety checks
# Verify we are inside a genuine QEMU source tree before touching anything.
# Checks for a combination of files that are unique to the qemu/ subdirectory
# and would not be present in the parent pve-qemu/ builder repo.
# -----------------------------------------------------------------------------
safety_checks() {
    log_section "Safety checks"

    local ok=true

    # 1. VERSION file must exist and look like a QEMU version (e.g. "10.1.2")
    if [[ ! -f VERSION ]]; then
        log_error "VERSION file not found. Run this script from inside the qemu/ subdirectory."
        ok=false
    else
        local ver
        ver=$(cat VERSION)
        if ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            log_error "VERSION file doesn't look like a QEMU version: '$ver'"
            ok=false
        else
            log_ok "QEMU version: $ver"
        fi
    fi

    # 2. Key source directories must be present
    local required_dirs=(hw target include hw/acpi hw/smbios hw/ide hw/nvme hw/usb)
    for d in "${required_dirs[@]}"; do
        if [[ ! -d "$d" ]]; then
            log_error "Required directory '$d' not found."
            ok=false
        fi
    done
    if $ok; then
        log_ok "Required source directories present"
    fi

    # 3. A few sentinel source files that must exist
    local required_files=(
        "include/hw/acpi/aml-build.h"
        "hw/acpi/aml-build.c"
        "hw/smbios/smbios.c"
        "hw/ide/core.c"
        "hw/nvme/ctrl.c"
        "hw/usb/dev-hid.c"
        "target/i386/cpu.c"
        "target/i386/kvm/kvm.c"
    )
    for f in "${required_files[@]}"; do
        if [[ ! -f "$f" ]]; then
            log_error "Required source file '$f' not found."
            ok=false
        fi
    done
    if $ok; then
        log_ok "Required source files present"
    fi

    # 4. Must NOT be run from the parent pve-qemu-builder directory
    if [[ -f Dockerfile || -d scripts && -f scripts/build-pve-qemu.sh ]]; then
        log_error "Looks like you're in the pve-qemu-builder directory, not qemu/."
        ok=false
    fi

    # 5. configure script should reference QEMU (quick sanity check)
    if [[ -f configure ]]; then
        if ! grep -q "QEMU" configure 2>/dev/null; then
            log_error "'configure' script doesn't look like QEMU's configure."
            ok=false
        else
            log_ok "configure script looks like QEMU"
        fi
    fi

    if ! $ok; then
        log_error "Safety checks failed. Aborting."
        exit 1
    fi

    log_ok "All safety checks passed -- operating on QEMU $(cat VERSION)"
}

# -----------------------------------------------------------------------------
# Platform detection
# GNU sed and BSD sed have different in-place syntax.
# -----------------------------------------------------------------------------
detect_sed() {
    if sed --version 2>/dev/null | grep -q "GNU"; then
        SED_BIN="sed"
        log_info "Detected GNU sed"
    elif [[ "$(uname)" == "Darwin" ]]; then
        # BSD sed requires an extension argument for -i
        SED_BIN="sed_bsd"
        log_info "Detected BSD sed (macOS)"
    else
        # Assume GNU-compatible
        SED_BIN="sed"
        log_info "Assuming GNU sed"
    fi
}

# Wrapper: abstracts GNU vs BSD sed -i behaviour
run_sed_inplace() {
    local expr="$1"
    local file="$2"
    if [[ "$SED_BIN" == "sed_bsd" ]]; then
        sed -i '' -e "$expr" "$file"
    else
        sed -i -e "$expr" "$file"
    fi
}

# -----------------------------------------------------------------------------
# verify_pattern FILE GREP_PATTERN
#
# Returns 0 if GREP_PATTERN is found in FILE (fixed-string match).
# Returns 1 if not found.
# Prints nothing -- callers decide how to handle the result.
# -----------------------------------------------------------------------------
verify_pattern() {
    local file="$1"
    local pattern="$2"
    grep -qF -- "$pattern" "$file" 2>/dev/null
}

# -----------------------------------------------------------------------------
# verify_pattern_re FILE GREP_REGEX
#
# Like verify_pattern but uses extended regex (-E) instead of fixed strings.
# Useful when the search term contains regex metacharacters.
# -----------------------------------------------------------------------------
verify_pattern_re() {
    local file="$1"
    local pattern="$2"
    grep -qE -- "$pattern" "$file" 2>/dev/null
}

# -----------------------------------------------------------------------------
# apply_sed DESCRIPTION FILE ALREADY_PATTERN SED_EXPRESSION
#
# The core workhorse. For each change:
#   1. Verify FILE exists
#   2. If ALREADY_PATTERN is found → change is already applied, skip (idempotent)
#   3. If the SED_EXPRESSION's search string is not found → source drifted, warn and skip
#   4. Otherwise, apply SED_EXPRESSION to FILE in-place
#
# Parameters:
#   DESCRIPTION    Human-readable description logged in summary
#   FILE           Path to source file (relative to qemu/)
#   ALREADY_PATTERN  A fixed string that will exist AFTER the change is applied.
#                    Used to detect idempotent re-runs. Pass "" to skip this check.
#   SED_EXPRESSION   The sed expression to apply (e.g. 's/old/new/')
#   FIND_PATTERN     Fixed string that must exist BEFORE the change (original text).
#                    Used to detect version drift.
#
# Note: FIND_PATTERN and ALREADY_PATTERN should be mutually exclusive -- if both
# exist simultaneously, the change is partially applied and we flag an error.
# -----------------------------------------------------------------------------
apply_sed() {
    local description="$1"
    local file="$2"
    local find_pattern="$3"     # must exist before the change (original text)
    local already_pattern="$4"  # must exist after the change (new text)
    local sed_expr="$5"

    echo ""
    log_info "${C_BOLD}${description}${C_RESET}"
    log_info "  File: $file"

    # --- File existence check ---
    if [[ ! -f "$file" ]]; then
        log_error "  File not found: $file"
        COUNT_ERRORS=$((COUNT_ERRORS + 1))
        ERROR_LOG+=("${description} -- file not found: $file")
        return 0
    fi

    # --- Idempotency check: already applied? ---
    if [[ -n "$already_pattern" ]] && verify_pattern "$file" "$already_pattern"; then
        log_skip "  Already applied (found post-change pattern)"
        COUNT_SKIPPED_ALREADY=$((COUNT_SKIPPED_ALREADY + 1))
        SKIPPED_ALREADY_LOG+=("${description} (${file})")
        return 0
    fi

    # --- Version drift check: original pattern present? ---
    if [[ -n "$find_pattern" ]] && ! verify_pattern "$file" "$find_pattern"; then
        log_warn "  Pattern not found -- source may have changed, skipping"
        log_warn "  Expected: $(echo "$find_pattern" | head -c 80)"
        COUNT_SKIPPED_MISSING=$((COUNT_SKIPPED_MISSING + 1))
        SKIPPED_MISSING_LOG+=("${description} (${file}) pattern: '${find_pattern}'")
        return 0
    fi

    # --- Consistency check: both patterns present would be a bug ---
    if [[ -n "$already_pattern" ]] && [[ -n "$find_pattern" ]]; then
        if verify_pattern "$file" "$already_pattern" && verify_pattern "$file" "$find_pattern"; then
            log_warn "  Both old and new patterns found simultaneously -- manual review needed"
            COUNT_ERRORS=$((COUNT_ERRORS + 1))
            ERROR_LOG+=("${description} -- conflicting state in ${file}")
            return 0
        fi
    fi

    # --- Apply ---
    if $DRY_RUN; then
        log_dry "  Would apply: $sed_expr"
        COUNT_APPLIED=$((COUNT_APPLIED + 1))
        APPLIED_LOG+=("[DRY] ${description} (${file})")
        return 0
    fi

    if run_sed_inplace "$sed_expr" "$file"; then
        log_ok "  Applied"
        COUNT_APPLIED=$((COUNT_APPLIED + 1))
        APPLIED_LOG+=("${description} (${file})")
    else
        log_error "  sed failed for: $sed_expr"
        COUNT_ERRORS=$((COUNT_ERRORS + 1))
        ERROR_LOG+=("${description} -- sed failed in ${file}")
    fi
}

# -----------------------------------------------------------------------------
# print_summary
#
# Prints a grouped summary of all actions at the end of the script.
# -----------------------------------------------------------------------------
print_summary() {
    local total=$((COUNT_APPLIED + COUNT_SKIPPED_MISSING + COUNT_SKIPPED_ALREADY + COUNT_ERRORS))

    echo ""
    echo -e "${C_BOLD}======================================================${C_RESET}"
    echo -e "${C_BOLD}  Anti-detection patch summary${C_RESET}"
    echo -e "${C_BOLD}======================================================${C_RESET}"
    printf "  Total changes evaluated : %d\n" "$total"

    if $DRY_RUN; then
        printf "  Would apply             : ${C_YELLOW}%d${C_RESET}\n" "$COUNT_APPLIED"
    else
        printf "  Applied                 : ${C_GREEN}%d${C_RESET}\n" "$COUNT_APPLIED"
    fi
    printf "  Already applied (skip)  : ${C_DIM}%d${C_RESET}\n" "$COUNT_SKIPPED_ALREADY"
    printf "  Pattern not found (skip): ${C_YELLOW}%d${C_RESET}\n" "$COUNT_SKIPPED_MISSING"
    printf "  Errors                  : ${C_RED}%d${C_RESET}\n" "$COUNT_ERRORS"

    if [[ ${#APPLIED_LOG[@]} -gt 0 ]]; then
        echo ""
        if $DRY_RUN; then
            echo -e "${C_YELLOW}  Would apply:${C_RESET}"
        else
            echo -e "${C_GREEN}  Applied:${C_RESET}"
        fi
        for entry in "${APPLIED_LOG[@]}"; do
            echo "    • $entry"
        done
    fi

    if [[ ${#SKIPPED_ALREADY_LOG[@]} -gt 0 ]]; then
        echo ""
        echo -e "${C_DIM}  Already applied (idempotent skip):${C_RESET}"
        for entry in "${SKIPPED_ALREADY_LOG[@]}"; do
            echo "    • $entry"
        done
    fi

    if [[ ${#SKIPPED_MISSING_LOG[@]} -gt 0 ]]; then
        echo ""
        echo -e "${C_YELLOW}  Pattern not found (version drift?):${C_RESET}"
        for entry in "${SKIPPED_MISSING_LOG[@]}"; do
            echo "    • $entry"
        done
    fi

    if [[ ${#ERROR_LOG[@]} -gt 0 ]]; then
        echo ""
        echo -e "${C_RED}  Errors:${C_RESET}"
        for entry in "${ERROR_LOG[@]}"; do
            echo "    • $entry"
        done
    fi

    echo ""
    echo -e "${C_BOLD}======================================================${C_RESET}"

    if [[ "$COUNT_ERRORS" -gt 0 ]]; then
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# run_patches -- HIGH-risk fingerprint suppression (H1-H8, H11)
#
# Replacement value rationale:
#   H2  "GenuineTMx86" -- real Transmeta Crusoe CPUID vendor string (defunct CPU,
#                        12 chars, not recognised as a hypervisor by any tool)
#   H4  "CentaurHauls" -- real VIA/Centaur CPUID vendor string (defunct CPU,
#                        12 chars, not recognised as a hypervisor by any tool)
#   H5  "ALASKA"/"A M I   " -- verbatim AMI BIOS OEM/Creator strings used by
#                        ASUS, ASRock, MSI and many other real motherboards
#   H7  "Default string" -- the literal AMI BIOS placeholder that appears on
#                        countless real boards when OEM branding is unconfigured
#   H11 0x5333:0x8d04 -- S3 Graphics Virge DX (real, defunct PCI GPU; no modern
#                        guest driver will bind to it, falls back to generic VGA)
# -----------------------------------------------------------------------------
run_patches() {

    # H1
    log_section "H1 -- CPUID hypervisor presence bit (ECX bit 31)"
    # CPUID leaf 0x1, ECX bit 31 is the standardised "running in hypervisor"
    # flag checked by every detection tool before anything else.
    # We comment the line out rather than delete it so a revert is a one-line
    # diff and the intent remains visible in the source history.
#    apply_sed \
#        'H1: Comment out unconditional CPUID_EXT_HYPERVISOR set' \
#        'target/i386/cpu.c' \
#        'env->features[FEAT_1_ECX] |= CPUID_EXT_HYPERVISOR;' \
#        '/* env->features[FEAT_1_ECX] |= CPUID_EXT_HYPERVISOR; */' \
#        's#env->features\[FEAT_1_ECX\] |= CPUID_EXT_HYPERVISOR;#/* env->features[FEAT_1_ECX] |= CPUID_EXT_HYPERVISOR; */#'

    # H2
    log_section "H2 -- KVM CPUID vendor string"
    # CPUID leaf 0x40000000 EBX/ECX/EDX = "KVMKVMKVM\0\0\0" when
    # expose_kvm=true.  "GenuineTMx86" is the real Transmeta Crusoe vendor
    # string -- a genuine, obscure x86 CPU that has never been a hypervisor.
    #
    # Quoting note: \\0 in a single-quoted sed BRE becomes \\ (literal \)
    # followed by 0 -- which matches the two characters \ and 0 in the C source.
#    apply_sed \
#        'H2: Replace KVM CPUID vendor "KVMKVMKVM" -> "GenuineTMx86"' \
#        'target/i386/kvm/kvm.c' \
#        'memcpy(signature, "KVMKVMKVM\0\0\0", 12);' \
#        'memcpy(signature, "GenuineTMx86", 12);' \
#        's#memcpy(signature, "KVMKVMKVM\\0\\0\\0", 12);#memcpy(signature, "GenuineTMx86", 12);#'

    # H3
    log_section "H3 -- TCG CPUID vendor string"
    # CPUID leaf 0x40000000 when expose_tcg=true (software emulation / TCG
    # mode).  Cleared to 12 spaces so the vendor field is blank.
    apply_sed \
        'H3: Clear TCG CPUID vendor "TCGTCGTCGTCG" -> 12 spaces' \
        'target/i386/cpu.c' \
        'memcpy(signature, "TCGTCGTCGTCG", 12);' \
        'memcpy(signature, "            ", 12);' \
        's#memcpy(signature, "TCGTCGTCGTCG", 12);#memcpy(signature, "            ", 12);#'

    # H4
    log_section "H4 -- Xen CPUID vendor string"
    # CPUID leaf 0x40000000 when Xen emulation is active.
    # "CentaurHauls" is the real VIA/Centaur CPUID vendor string -- a genuine
    # x86 CPU vendor (VIA C3/C7/Nano) that has never been a hypervisor.
    # Using a distinct replacement from H2 ensures the idempotency ALREADY
    # check for each entry is unambiguous within the same source file.
    apply_sed \
        'H4: Replace Xen CPUID vendor "XenVMMXenVMM" -> "CentaurHauls"' \
        'target/i386/kvm/kvm.c' \
        'memcpy(signature, "XenVMMXenVMM", 12);' \
        'memcpy(signature, "CentaurHauls", 12);' \
        's#memcpy(signature, "XenVMMXenVMM", 12);#memcpy(signature, "CentaurHauls", 12);#'

    # H5
    log_section "H5 -- ACPI OEM ID and Creator strings (BOCHS / BXPC)"
    # ACPI_BUILD_APPNAME6 ("BOCHS ") is written as OEM ID in the header of
    # every ACPI table this QEMU instance produces.
    # ACPI_BUILD_APPNAME8 ("BXPC    ") is written as the Creator ID in every
    # AML table -- visible via acpidump(8) and Windows WMI from the guest.
    #
    # "ALASKA" and "A M I   " are the verbatim AMI BIOS strings used by ASUS,
    # ASRock, MSI and the majority of real consumer/workstation boards.
    # String widths are preserved: APPNAME6 = 6 chars, APPNAME8 = 8 chars.
    apply_sed \
        'H5a: Replace ACPI OEM ID "BOCHS " -> "ALASKA" (AMI BIOS, 6 chars)' \
        'include/hw/acpi/aml-build.h' \
        '"BOCHS "' \
        '"ALASKA"' \
        's#"BOCHS "#"ALASKA"#'

    apply_sed \
        'H5b: Replace ACPI Creator/Table ID "BXPC    " -> "A M I   " (AMI BIOS, 8 chars)' \
        'include/hw/acpi/aml-build.h' \
        '"BXPC    "' \
        '"A M I   "' \
        's#"BXPC    "#"A M I   "#'

    # H6
    log_section "H6 -- ACPI FADT Hypervisor Vendor Identity field"
    # ACPI 6.0+ FADT offset 0x88: 8-byte "Hypervisor Vendor Identity" string.
    # On real bare-metal this field is all-zeros (no hypervisor present).
    # Passing an empty string to build_append_padded_str zero-fills all 8 bytes,
    # matching real hardware behaviour.
    # We match only up to the 8th argument to avoid quoting the C '\0' char
    # constant that follows -- the rest of the line is left unchanged.
    apply_sed \
        'H6: Clear FADT Hypervisor Vendor Identity "QEMU" -> zero-fill (empty string)' \
        'hw/acpi/aml-build.c' \
        'build_append_padded_str(tbl, "QEMU", 8,' \
        'build_append_padded_str(tbl, "", 8,' \
        's#build_append_padded_str(tbl, "QEMU", 8,#build_append_padded_str(tbl, "", 8,#'

    # H7
    log_section "H7 -- SMBIOS manufacturer default"
    # smbios_set_defaults("QEMU", ...) seeds the manufacturer field for SMBIOS
    # Type 1 (System), Type 2 (Board), Type 3 (Chassis), Type 4 (Processor)
    # and Type 17 (Memory) all visible via dmidecode(8) and WMI from guests.
    #
    # "Default string" is the literal AMI BIOS placeholder used verbatim on
    # countless real ASRock, Gigabyte entry-level and OEM boards when the
    # manufacturer has not filled in their branding.  It looks plausible and
    # does not falsely claim to be any specific vendor.
    #
    # The first argument is the manufacturer; the second and third differ per
    # architecture (mc->desc / product / mc->name) the sed expr only touches
    # the first argument so all four call sites are handled by one expression.
    for _h7_file in \
        'hw/i386/fw_cfg.c' \
        'hw/arm/virt.c'    \
        'hw/riscv/virt.c'  \
        'hw/loongarch/virt.c'
    do
        apply_sed \
            "H7: Replace SMBIOS manufacturer \"QEMU\" -> \"Default string\" in ${_h7_file}" \
            "$_h7_file" \
            'smbios_set_defaults("QEMU",' \
            'smbios_set_defaults("Default string",' \
            's#smbios_set_defaults("QEMU",#smbios_set_defaults("Default string",#'
    done

    # H8
    log_section "H8 -- Firmware config (fw_cfg) device signature"
    # WARNING -- READ BEFORE APPLYING
    #
    # FW_CFG_SIGNATURE (I/O selector 0x00) returns the 4-byte magic "QEMU"
    # that SeaBIOS and OVMF read to discover the fw_cfg device.  Changing
    # it here will BREAK fw_cfg-dependent boot features unless you also
    # patch the matching check in your BIOS/UEFI firmware source:
    #   SeaBIOS: src/fw/paravirt.c  qemu_preinit()
    #   OVMF:    OvmfPkg/Library/QemuFwCfgLib/QemuFwCfgLib.c
    #
    # If you are using unmodified SeaBIOS or OVMF, applying this patch
    # will disable: kernel/initrd injection, boot-order passing, SMBIOS
    # table injection, and other fw_cfg-provided boot-time configuration.
    #
    # The DMA acceleration signature (0x51454d5520434647 "QEMU CFG") in
    # hw/nvram/fw_cfg.c and include/standard-headers/linux/qemu_fw_cfg.h
    # is intentionally left unchanged -- it is only used for the optional
    # DMA path and requires a matching change on the guest driver side.
    #
    # In the sed expression, \* escapes the literal * in "(char *)" inside
    # sed BRE; in the replacement the * is written unescaped (literal in RHS).
#    apply_sed \
#        'H8: Replace fw_cfg signature "QEMU" -> "BIOS"  !! requires matching BIOS patch !!' \
#        'hw/nvram/fw_cfg.c' \
#        '(char *)"QEMU", 4' \
#        '(char *)"BIOS", 4' \
#        's#(char \*)"QEMU", 4#(char *)"BIOS", 4#'

    # H11
    log_section "H11 -- PCI VGA vendor/device IDs (0x1234:0x1111)"
    # Standard VGA (vga-pci.c) and Bochs framebuffer (bochs-display.c) both
    # advertise PCI_VENDOR_ID_QEMU (0x1234) and PCI_DEVICE_ID_QEMU_VGA (0x1111).
    # This pair is in every anti-VM signature database.
    #
    # Replacement: S3 Graphics 0x5333, device 0x8d04 (Virge DX).
    #   • Real PCI VGA device from a defunct manufacturer (S3/VIA).
    #   • No modern guest OS ships a driver that will bind to it -- the guest
    #     falls back to the generic VGA / VESA framebuffer driver silently.
    #   • Not present in any hypervisor detection database.
    #   • Class code (0x0300 VGA) and BAR layout are unchanged, so the device
    #     still works as a display adapter via the generic path.
    #
    # Note: PCI_VENDOR_ID_QEMU is left unchanged in include/hw/pci/pci.h so
    # that the IPMI and edu devices (L-tier, not patched here) are unaffected.
    # We patch the assignments directly in the two display device files.
#    for _h11_file in 'hw/display/vga-pci.c' 'hw/display/bochs-display.c'; do
#        apply_sed \
#            "H11a: Replace PCI vendor PCI_VENDOR_ID_QEMU -> 0x5333 (S3 Graphics) in ${_h11_file}" \
#            "$_h11_file" \
#            'k->vendor_id = PCI_VENDOR_ID_QEMU;' \
#            'k->vendor_id = 0x5333;' \
#            's#k->vendor_id = PCI_VENDOR_ID_QEMU;#k->vendor_id = 0x5333;#'

#        apply_sed \
#            "H11b: Replace PCI device PCI_DEVICE_ID_QEMU_VGA -> 0x8d04 (Virge DX) in ${_h11_file}" \
#            "$_h11_file" \
#            'k->device_id = PCI_DEVICE_ID_QEMU_VGA;' \
#            'k->device_id = 0x8d04;' \
#            's#k->device_id = PCI_DEVICE_ID_QEMU_VGA;#k->device_id = 0x8d04;#'
#    done

    # M1
    log_section "M1 -- IDE drive serial and model strings"
    # hw/ide/core.c sets the default ATA serial number format (printf template)
    # and model strings for virtual HARDDISK, DVD-ROM, and MICRODRIVE devices.
    # These appear in ATA IDENTIFY DEVICE (word 10-19/27-46) and are visible
    # to guests via hdparm -I, lshw, udevadm info, and /sys/block/*/device/.
    #
    # Replacements: WD (Western Digital) and HL-DT-ST (LG/HLDS OEM)
    # two of the most common drive vendors in real consumer systems.
    apply_sed \
        'M1a: IDE serial format "QM%05d" -> "WD%05d"' \
        'hw/ide/core.c' \
        '"QM%05d"' \
        '"WD%05d"' \
        's#"QM%05d"#"WD%05d"#'

    apply_sed \
        'M1b: IDE DVD-ROM model "QEMU DVD-ROM" -> "HL-DT-ST DVD-ROM"' \
        'hw/ide/core.c' \
        '"QEMU DVD-ROM"' \
        '"HL-DT-ST DVD-ROM"' \
        's#"QEMU DVD-ROM"#"HL-DT-ST DVD-ROM"#'

    apply_sed \
        'M1c: IDE Microdrive model "QEMU MICRODRIVE" -> "HITACHI Microdrive"' \
        'hw/ide/core.c' \
        '"QEMU MICRODRIVE"' \
        '"HITACHI Microdrive"' \
        's#"QEMU MICRODRIVE"#"HITACHI Microdrive"#'

    apply_sed \
        'M1d: IDE Harddisk model "QEMU HARDDISK" -> "KINGSTON SA400S37"' \
        'hw/ide/core.c' \
        '"QEMU HARDDISK"' \
        '"KINGSTON SA400S37"' \
        's#"QEMU HARDDISK"#"KINGSTON SA400S37"#'

    # M2
    log_section "M2 -- ATAPI INQUIRY vendor and product strings"
    # hw/ide/atapi.c fills the SCSI INQUIRY response for the virtual optical
    # drive (ATAPI mode).  T10 vendor (8 bytes) and product (16 bytes) are
    # space-padded and visible via sg_inq(8), udevadm info, and the guest
    # /sys/bus/scsi/devices/ hierarchy.
    #
    # "HL-DT-ST" is the OEM brand used by LG HLDS on virtually all shipping
    # optical drives.  "DVD-ROM GH22NS50" is a real LG OEM model number.
    apply_sed \
        'M2a: ATAPI INQUIRY vendor "QEMU" -> "HL-DT-ST" (LG/HLDS OEM, 8 chars)' \
        'hw/ide/atapi.c' \
        'padstr8(buf + 8, 8, "QEMU")' \
        'padstr8(buf + 8, 8, "HL-DT-ST")' \
        's#padstr8(buf + 8, 8, "QEMU")#padstr8(buf + 8, 8, "HL-DT-ST")#'

    apply_sed \
        'M2b: ATAPI INQUIRY product "QEMU DVD-ROM" -> "DVD-ROM GH22NS50" (LG)' \
        'hw/ide/atapi.c' \
        'padstr8(buf + 16, 16, "QEMU DVD-ROM")' \
        'padstr8(buf + 16, 16, "DVD-ROM GH22NS50")' \
        's#padstr8(buf + 16, 16, "QEMU DVD-ROM")#padstr8(buf + 16, 16, "DVD-ROM GH22NS50")#'

    # M3
    log_section "M3 -- SCSI vendor and product strings"
    # hw/scsi/scsi-disk.c sets vendor/product for the virtual SCSI disk and
    # optical drive; hw/scsi/mptconfig.c sets the MPT Fusion HBA product name.
    # All fields are visible via sg_inq(8), sdparm(8), and
    # /sys/class/scsi_device/*/device/{vendor,model} in the guest.
    #
    # "ATA     " (8 bytes, space-padded) is the vendor written by real ATA disks
    # behind a SCSI/SAT bridge -- extremely common for SATA SSDs.
    # "WDC WD10EZEX" and "MATSHITA CD-ROM " are real OEM product strings.
    # "LSI MPT Fusion" is the correct product string for the LSI/Broadcom SAS HBA
    # that the MPT Fusion emulation is modelled after.
    apply_sed \
        'M3a: SCSI disk vendor "QEMU" -> "ATA     " in hw/scsi/scsi-disk.c' \
        'hw/scsi/scsi-disk.c' \
        's->vendor = g_strdup("QEMU")' \
        's->vendor = g_strdup("ATA     ")' \
        's#s->vendor = g_strdup("QEMU")#s->vendor = g_strdup("ATA     ")#'

    apply_sed \
        'M3b: SCSI harddisk product "QEMU HARDDISK" -> "WDC WD10EZEX"' \
        'hw/scsi/scsi-disk.c' \
        'g_strdup("QEMU HARDDISK")' \
        'g_strdup("WDC WD10EZEX")' \
        's#g_strdup("QEMU HARDDISK")#g_strdup("WDC WD10EZEX")#'

    apply_sed \
        'M3c: SCSI CD-ROM product "QEMU CD-ROM" -> "MATSHITA CD-ROM "' \
        'hw/scsi/scsi-disk.c' \
        'g_strdup("QEMU CD-ROM")' \
        'g_strdup("MATSHITA CD-ROM ")' \
        's#g_strdup("QEMU CD-ROM")#g_strdup("MATSHITA CD-ROM ")#'

    apply_sed \
        'M3d: MPT Fusion HBA product "QEMU MPT Fusion" -> "LSI MPT Fusion" in mptconfig.c' \
        'hw/scsi/mptconfig.c' \
        '"QEMU MPT Fusion"' \
        '"LSI MPT Fusion"' \
        's#"QEMU MPT Fusion"#"LSI MPT Fusion"#g'

    apply_sed \
        'M3e: MPT Fusion HBA vendor "QEMU" -> "LSI" in mptconfig.c' \
        'hw/scsi/mptconfig.c' \
        '"QEMU",' \
        '"LSI",' \
        's#"QEMU",#"LSI",#'

    # M4
    log_section "M4 -- UFS SCSI INQUIRY vendor and product strings"
    # hw/ufs/lu.c fills the SCSI INQUIRY response for the virtual UFS logical
    # unit.  Vendor (8 bytes) and product (16 bytes) are padded with spaces.
    # Visible via sg_inq(8) and /sys/class/scsi_device/ in the guest.
    #
    # Samsung is the dominant UFS chip vendor; KLUCG4J1EA-B0C1 is a real
    # Samsung UFS 2.1 chip product code used in mobile platforms.
    apply_sed \
        'M4a: UFS INQUIRY vendor "QEMU" -> "SAMSUNG" in hw/ufs/lu.c' \
        'hw/ufs/lu.c' \
        'outbuf[8], 8, "QEMU"' \
        'outbuf[8], 8, "SAMSUNG"' \
        's#outbuf\[8\], 8, "QEMU"#outbuf[8], 8, "SAMSUNG"#'

    apply_sed \
        'M4b: UFS INQUIRY product "QEMU UFS" -> "KLUCG4J1EA-B0C1" in hw/ufs/lu.c' \
        'hw/ufs/lu.c' \
        'outbuf[16], 16, "QEMU UFS"' \
        'outbuf[16], 16, "KLUCG4J1EA-B0C1"' \
        's#outbuf\[16\], 16, "QEMU UFS"#outbuf[16], 16, "KLUCG4J1EA-B0C1"#'

    # M5
    log_section "M5 -- NVMe controller model and firmware revision"
    # hw/nvme/ctrl.c populates the NVMe Identify Controller response (CNS=0x01).
    # Model Number (mn, 40 bytes) and Firmware Revision (fr, 8 bytes) are
    # readable in guests via: nvme id-ctrl /dev/nvme0 | grep -E "mn|fr"
    # and are also exposed through /sys/class/nvme/nvme0/{model,firmware_rev}.
    #
    # "Samsung SSD 970 EVO" is a real high-volume NVMe SSD model.
    # "EXA72H3Q" is a real Samsung 970 EVO firmware revision string.
    # The QEMU_VERSION macro reference in the fr field is replaced with a
    # static string so the firmware revision no longer leaks the QEMU version.
    apply_sed \
        'M5a: NVMe model "QEMU NVMe Ctrl" -> "Samsung SSD 970 EVO"' \
        'hw/nvme/ctrl.c' \
        '"QEMU NVMe Ctrl"' \
        '"Samsung SSD 970 EVO"' \
        's#"QEMU NVMe Ctrl"#"Samsung SSD 970 EVO"#'

    apply_sed \
        'M5b: NVMe firmware QEMU_VERSION macro -> "EXA72H3Q" (static Samsung rev)' \
        'hw/nvme/ctrl.c' \
        ', QEMU_VERSION,' \
        ', "EXA72H3Q",' \
        's#, QEMU_VERSION,#, "EXA72H3Q",#'

    # M6
    log_section "M6 -- USB vendor ID 0x46f4 (CRC16 of \"QEMU\")"
    # 0x46f4 is documented in the QEMU source as CRC16("QEMU") and is used as
    # the USB idVendor across five USB device implementations.  Any tool that
    # queries USB descriptors (lsusb, udevadm info, Windows Device Manager)
    # will expose it.
    #
    # Replacement: 0x04b3 (IBM Corp.) a real, allocated USB vendor ID with
    # a broad product catalogue, unlikely to be associated with a hypervisor.
    apply_sed \
        'M6a: USB U2F key vendor 0x46f4 -> 0x04b3 (IBM Corp.) in hw/usb/u2f.c' \
        'hw/usb/u2f.c' \
        'U2F_KEY_VENDOR_NUM     0x46f4' \
        'U2F_KEY_VENDOR_NUM     0x04b3' \
        's#U2F_KEY_VENDOR_NUM     0x46f4#U2F_KEY_VENDOR_NUM     0x04b3#'

    apply_sed \
        'M6b: USB audio vendor 0x46f4 -> 0x04b3 in hw/usb/dev-audio.c' \
        'hw/usb/dev-audio.c' \
        'USBAUDIO_VENDOR_NUM     0x46f4' \
        'USBAUDIO_VENDOR_NUM     0x04b3' \
        's#USBAUDIO_VENDOR_NUM     0x46f4#USBAUDIO_VENDOR_NUM     0x04b3#'

    for _m6_file in \
        'hw/usb/dev-storage.c' \
        'hw/usb/dev-uas.c'     \
        'hw/usb/dev-mtp.c'
    do
        apply_sed \
            "M6c: USB .idVendor 0x46f4 -> 0x04b3 (IBM Corp.) in ${_m6_file}" \
            "$_m6_file" \
            '.idVendor          = 0x46f4,' \
            '.idVendor          = 0x04b3,' \
            's#\.idVendor          = 0x46f4,#.idVendor          = 0x04b3,#'
    done

    # M7
    log_section "M7 -- USB product and manufacturer strings"
    # USB descriptor strings are retrieved by the guest via the GET_DESCRIPTOR
    # request for String Descriptors and exposed through:
    #   - lsusb / lsusb -v  (ID_VENDOR_FROM_DATABASE, ID_MODEL)
    #   - udevadm info (ID_VENDOR, ID_MODEL properties)
    #   - Windows Device Manager (manufacturer/product fields)
    # Manufacturer is replaced with "Generic" -- a common real-world placeholder
    # used by no-name and white-label USB devices.

    # dev-hid.c (mouse, tablet, keyboard)
    apply_sed \
        'M7a: USB HID manufacturer "QEMU" -> "Generic" in dev-hid.c' \
        'hw/usb/dev-hid.c' \
        '[STR_MANUFACTURER]     = "QEMU",' \
        '[STR_MANUFACTURER]     = "Generic",' \
        's#\[STR_MANUFACTURER\]     = "QEMU",#[STR_MANUFACTURER]     = "Generic",#'

    apply_sed \
        'M7b: USB Mouse product "QEMU USB Mouse" -> "USB Optical Mouse" in dev-hid.c' \
        'hw/usb/dev-hid.c' \
        '"QEMU USB Mouse"' \
        '"USB Optical Mouse"' \
        's#"QEMU USB Mouse"#"USB Optical Mouse"#g'

    apply_sed \
        'M7c: USB Tablet product "QEMU USB Tablet" -> "USB Tablet" in dev-hid.c' \
        'hw/usb/dev-hid.c' \
        '"QEMU USB Tablet"' \
        '"USB Tablet"' \
        's#"QEMU USB Tablet"#"USB Tablet"#g'

    apply_sed \
        'M7d: USB Keyboard product "QEMU USB Keyboard" -> "USB Keyboard" in dev-hid.c' \
        'hw/usb/dev-hid.c' \
        '"QEMU USB Keyboard"' \
        '"USB Keyboard"' \
        's#"QEMU USB Keyboard"#"USB Keyboard"#g'

    # dev-hub.c
    apply_sed \
        'M7e: USB Hub manufacturer "QEMU" -> "Generic" in dev-hub.c' \
        'hw/usb/dev-hub.c' \
        '[STR_MANUFACTURER] = "QEMU",' \
        '[STR_MANUFACTURER] = "Generic",' \
        's#\[STR_MANUFACTURER\] = "QEMU",#[STR_MANUFACTURER] = "Generic",#'

    apply_sed \
        'M7f: USB Hub product "QEMU USB Hub" -> "USB 2.0 Hub" in dev-hub.c' \
        'hw/usb/dev-hub.c' \
        '"QEMU USB Hub"' \
        '"USB 2.0 Hub"' \
        's#"QEMU USB Hub"#"USB 2.0 Hub"#g'

    # dev-storage.c
    apply_sed \
        'M7g: USB Storage manufacturer "QEMU" -> "Generic" in dev-storage.c' \
        'hw/usb/dev-storage.c' \
        '[STR_MANUFACTURER] = "QEMU",' \
        '[STR_MANUFACTURER] = "Generic",' \
        's#\[STR_MANUFACTURER\] = "QEMU",#[STR_MANUFACTURER] = "Generic",#'

    apply_sed \
        'M7h: USB HARDDRIVE product "QEMU USB HARDDRIVE" -> "USB Flash Drive" in dev-storage.c' \
        'hw/usb/dev-storage.c' \
        '"QEMU USB HARDDRIVE"' \
        '"USB Flash Drive"' \
        's#"QEMU USB HARDDRIVE"#"USB Flash Drive"#'

    apply_sed \
        'M7i: USB MSD product_desc "QEMU USB MSD" -> "USB Mass Storage" in dev-storage.c' \
        'hw/usb/dev-storage.c' \
        '"QEMU USB MSD"' \
        '"USB Mass Storage"' \
        's#"QEMU USB MSD"#"USB Mass Storage"#'

    # dev-audio.c
    apply_sed \
        'M7j: USB Audio manufacturer "QEMU" -> "Generic" in dev-audio.c' \
        'hw/usb/dev-audio.c' \
        '[STRING_MANUFACTURER]       = "QEMU",' \
        '[STRING_MANUFACTURER]       = "Generic",' \
        's#\[STRING_MANUFACTURER\]       = "QEMU",#[STRING_MANUFACTURER]       = "Generic",#'

    apply_sed \
        'M7k: USB Audio product "QEMU USB Audio" -> "USB Audio Device" in dev-audio.c' \
        'hw/usb/dev-audio.c' \
        '"QEMU USB Audio",' \
        '"USB Audio Device",' \
        's#"QEMU USB Audio",#"USB Audio Device",#'

    apply_sed \
        'M7l: USB Audio product_desc "QEMU USB Audio Interface" -> "USB Audio Interface"' \
        'hw/usb/dev-audio.c' \
        '"QEMU USB Audio Interface"' \
        '"USB Audio Interface"' \
        's#"QEMU USB Audio Interface"#"USB Audio Interface"#'

    # dev-smartcard-reader.c (CCID smart card reader)
    apply_sed \
        'M7m: CCID vendor define "QEMU" -> "Generic" in dev-smartcard-reader.c' \
        'hw/usb/dev-smartcard-reader.c' \
        'CCID_VENDOR_DESCRIPTION         "QEMU"' \
        'CCID_VENDOR_DESCRIPTION         "Generic"' \
        's#CCID_VENDOR_DESCRIPTION         "QEMU"#CCID_VENDOR_DESCRIPTION         "Generic"#'

    apply_sed \
        'M7n: CCID manufacturer string "QEMU" -> "Generic" in dev-smartcard-reader.c' \
        'hw/usb/dev-smartcard-reader.c' \
        '[STR_MANUFACTURER]  = "QEMU",' \
        '[STR_MANUFACTURER]  = "Generic",' \
        's#\[STR_MANUFACTURER\]  = "QEMU",#[STR_MANUFACTURER]  = "Generic",#'

    apply_sed \
        'M7o: CCID product "QEMU USB CCID" -> "USB Smart Card Reader" in dev-smartcard-reader.c' \
        'hw/usb/dev-smartcard-reader.c' \
        '"QEMU USB CCID"' \
        '"USB Smart Card Reader"' \
        's#"QEMU USB CCID"#"USB Smart Card Reader"#g'

    # dev-serial.c (USB-to-serial and Braille display)
    apply_sed \
        'M7p: USB Serial manufacturer "QEMU" -> "Generic" in dev-serial.c' \
        'hw/usb/dev-serial.c' \
        '[STR_MANUFACTURER]    = "QEMU",' \
        '[STR_MANUFACTURER]    = "Generic",' \
        's#\[STR_MANUFACTURER\]    = "QEMU",#[STR_MANUFACTURER]    = "Generic",#'

    apply_sed \
        'M7q: USB Serial product string "QEMU USB SERIAL" -> "USB Serial Adapter"' \
        'hw/usb/dev-serial.c' \
        '"QEMU USB SERIAL"' \
        '"USB Serial Adapter"' \
        's#"QEMU USB SERIAL"#"USB Serial Adapter"#'

    apply_sed \
        'M7r: USB Serial product_desc "QEMU USB Serial" -> "USB Serial Adapter"' \
        'hw/usb/dev-serial.c' \
        '"QEMU USB Serial"' \
        '"USB Serial Adapter"' \
        's#"QEMU USB Serial"#"USB Serial Adapter"#'

    apply_sed \
        'M7s: USB Braille product string "QEMU USB BAUM BRAILLE" -> "USB Braille Display"' \
        'hw/usb/dev-serial.c' \
        '"QEMU USB BAUM BRAILLE"' \
        '"USB Braille Display"' \
        's#"QEMU USB BAUM BRAILLE"#"USB Braille Display"#'

    apply_sed \
        'M7t: USB Braille product_desc "QEMU USB Braille" -> "USB Braille Display"' \
        'hw/usb/dev-serial.c' \
        '"QEMU USB Braille"' \
        '"USB Braille Display"' \
        's#"QEMU USB Braille"#"USB Braille Display"#'

    # dev-mtp.c (USB Media Transfer Protocol)
    apply_sed \
        'M7u: USB MTP manufacturer define "QEMU" -> "Generic" in dev-mtp.c' \
        'hw/usb/dev-mtp.c' \
        'MTP_MANUFACTURER  "QEMU"' \
        'MTP_MANUFACTURER  "Generic"' \
        's#MTP_MANUFACTURER  "QEMU"#MTP_MANUFACTURER  "Generic"#'

    apply_sed \
        'M7v: USB MTP product_desc "QEMU USB MTP" -> "USB Media Transfer" in dev-mtp.c' \
        'hw/usb/dev-mtp.c' \
        '"QEMU USB MTP"' \
        '"USB Media Transfer"' \
        's#"QEMU USB MTP"#"USB Media Transfer"#'

    # dev-network.c (USB CDC/RNDIS network adapter)
    apply_sed \
        'M7w: USB Network product_desc "QEMU USB Network Interface" -> "USB Network Adapter"' \
        'hw/usb/dev-network.c' \
        '"QEMU USB Network Interface"' \
        '"USB Network Adapter"' \
        's#"QEMU USB Network Interface"#"USB Network Adapter"#'

    # M8
    log_section "M8 -- USB HID vendor ID 0x0627"
    # hw/usb/dev-hid.c uses vendor ID 0x0627 in all six USB HID device
    # descriptors (mouse × 2 configs, tablet × 2, keyboard × 2).
    # 0x0627 is an unallocated/QEMU-internal value not assigned to any real
    # manufacturer in the USB-IF registry and appears in VM detection databases.
    #
    # Replacement: 0x046d (Logitech International) the dominant USB HID
    # vendor; having Logitech-vendor'd HID devices is entirely normal.
    apply_sed \
        'M8: USB HID vendor 0x0627 -> 0x046d (Logitech) in dev-hid.c (all 6 descriptors)' \
        'hw/usb/dev-hid.c' \
        '.idVendor          = 0x0627,' \
        '.idVendor          = 0x046d,' \
        's#\.idVendor          = 0x0627,#.idVendor          = 0x046d,#g'

    # M9
    log_section "M9 -- HDA audio codec vendor ID"
    # hw/audio/hda-codec.c defines QEMU_HDA_ID_VENDOR as 0x1af4 (Red Hat
    # Qumranet) the same vendor as virtio.  This is embedded in the HDA
    # codec PCI subsystem ID and is visible via /proc/asound/cards,
    # aplay -l, and the HDA codec sysfs tree in the guest.
    #
    # Replacement: 0x10ec (Realtek Semiconductor) the most common real HDA
    # codec vendor, present on the vast majority of consumer motherboards.
    apply_sed \
        'M9: HDA codec vendor 0x1af4 -> 0x10ec (Realtek) in hw/audio/hda-codec.c' \
        'hw/audio/hda-codec.c' \
        'QEMU_HDA_ID_VENDOR  0x1af4' \
        'QEMU_HDA_ID_VENDOR  0x10ec' \
        's#QEMU_HDA_ID_VENDOR  0x1af4#QEMU_HDA_ID_VENDOR  0x10ec#'

    # M10
    log_section "M10 -- Hyper-V enlightenment vendor ID default"
    # target/i386/cpu.c sets the default hv-vendor-id to "Microsoft Hv" when
    # KVM Hyper-V enlightenments are enabled and the user has not specified a
    # custom vendor ID.  This string is exposed via CPUID leaf 0x40000000
    # EBX/ECX/EDX (12 bytes) and is checked by Windows to enable enlightenments
    # and by anti-VM tools as a Hyper-V/hypervisor indicator.
    #
    # Replacement: "AuthenticAMD" -- the real AMD CPUID vendor string (12 chars).
    # Windows and Linux will not recognise it as a Hyper-V vendor and will not
    # enable Hyper-V enlightenments, which is acceptable for detection avoidance.
#    apply_sed \
#        'M10: Hyper-V vendor default "Microsoft Hv" -> "AuthenticAMD"' \
#        'target/i386/cpu.c' \
#        '"hv-vendor-id", "Microsoft Hv",' \
#        '"hv-vendor-id", "AuthenticAMD",' \
#        's#"hv-vendor-id", "Microsoft Hv",#"hv-vendor-id", "AuthenticAMD",#'

    # M11
    log_section "M11 -- SMBIOS BIOS characteristics extension byte: VM flag"
    # hw/smbios/smbios.c Type 0 (BIOS Information) sets extension byte [1]
    # to 0x14 = 0x10 (VM indicator, SMBIOS 2.6 Table 75) | 0x04 (SVVP certified).
    # dmidecode(8), WMI Win32_BIOS.BIOSCharacteristics, and virtually every
    # anti-VM tool explicitly check this bit.  Clearing it to 0x00 claims
    # "no VM-specific BIOS features", matching a real bare-metal board.
    #
    # Note: if smbios_type0.uefi is set, the code later ORs in 0x08 (UEFI
    # Specification Supported), so UEFI guests will still see 0x08, not 0x00.
#    apply_sed \
#        'M11: Clear SMBIOS BIOS VM flag: extension_bytes[1] = 0x14 -> 0x00' \
#        'hw/smbios/smbios.c' \
#        'extension_bytes[1] = 0x14;' \
#        'extension_bytes[1] = 0x00;' \
#        's#extension_bytes\[1\] = 0x14;#extension_bytes[1] = 0x00;#'

    # M12
    log_section "M12 -- SMBIOS processor cache handles"
    # hw/smbios/smbios.c Type 4 (Processor Information) uses 0xFFFF for all
    # three cache handles (L1/L2/L3), meaning "cache information not provided".
    # Anti-VM fingerprinting tools recognise this triple-0xFFFF pattern as QEMU.
    # We replace them with small handle numbers that look like real SMBIOS
    # handle assignments from a firmware that generates Type 7 (Cache Info)
    # records at handles 2, 3, 4 (following Type 4 at handle 1).
    apply_sed \
        'M12a: SMBIOS L1 cache handle 0xFFFF -> 0x0002' \
        'hw/smbios/smbios.c' \
        'l1_cache_handle = cpu_to_le16(0xFFFF)' \
        'l1_cache_handle = cpu_to_le16(0x0002)' \
        's#l1_cache_handle = cpu_to_le16(0xFFFF)#l1_cache_handle = cpu_to_le16(0x0002)#'

    apply_sed \
        'M12b: SMBIOS L2 cache handle 0xFFFF -> 0x0003' \
        'hw/smbios/smbios.c' \
        'l2_cache_handle = cpu_to_le16(0xFFFF)' \
        'l2_cache_handle = cpu_to_le16(0x0003)' \
        's#l2_cache_handle = cpu_to_le16(0xFFFF)#l2_cache_handle = cpu_to_le16(0x0003)#'

    apply_sed \
        'M12c: SMBIOS L3 cache handle 0xFFFF -> 0x0004' \
        'hw/smbios/smbios.c' \
        'l3_cache_handle = cpu_to_le16(0xFFFF)' \
        'l3_cache_handle = cpu_to_le16(0x0004)' \
        's#l3_cache_handle = cpu_to_le16(0xFFFF)#l3_cache_handle = cpu_to_le16(0x0004)#'

    # M13
    log_section "M13 -- SMBIOS memory type and voltage fields"
    # hw/smbios/smbios.c Type 17 (Memory Device) sets:
    #   memory_type = 0x07  (RAM -- the generic "unknown type" fallback)
    #   type_detail = 0x02  (Other -- equally generic)
    #   min/max/configured_voltage = 0  (Unknown)
    # A real DDR4 DIMM would report:
    #   memory_type = 0x1a  (DDR4, SMBIOS 3.2 Table 76)
    #   type_detail = 0x0080 (Synchronous, bit 7)
    #   voltages    = 1200 mV  (DDR4 nominal 1.2 V)
    # These values are checked by dmidecode, WMI Win32_PhysicalMemory, and
    # anti-VM tools as RAM generics are a strong emulator indicator.
    apply_sed \
        'M13a: SMBIOS memory type 0x07 (RAM) -> 0x1a (DDR4)' \
        'hw/smbios/smbios.c' \
        'memory_type = 0x07;' \
        'memory_type = 0x1a;' \
        's#memory_type = 0x07;#memory_type = 0x1a;#'

    apply_sed \
        'M13b: SMBIOS type_detail 0x02 (Other) -> 0x0080 (Synchronous, DDR4)' \
        'hw/smbios/smbios.c' \
        'type_detail = cpu_to_le16(0x02);' \
        'type_detail = cpu_to_le16(0x0080);' \
        's#type_detail = cpu_to_le16(0x02);#type_detail = cpu_to_le16(0x0080);#'

    apply_sed \
        'M13c: SMBIOS minimum_voltage 0 (Unknown) -> 1200 mV (DDR4 1.2 V)' \
        'hw/smbios/smbios.c' \
        'minimum_voltage = cpu_to_le16(0);' \
        'minimum_voltage = cpu_to_le16(1200);' \
        's#minimum_voltage = cpu_to_le16(0);#minimum_voltage = cpu_to_le16(1200);#'

    apply_sed \
        'M13d: SMBIOS maximum_voltage 0 (Unknown) -> 1200 mV (DDR4 1.2 V)' \
        'hw/smbios/smbios.c' \
        'maximum_voltage = cpu_to_le16(0);' \
        'maximum_voltage = cpu_to_le16(1200);' \
        's#maximum_voltage = cpu_to_le16(0);#maximum_voltage = cpu_to_le16(1200);#'

    apply_sed \
        'M13e: SMBIOS configured_voltage 0 (Unknown) -> 1200 mV (DDR4 1.2 V)' \
        'hw/smbios/smbios.c' \
        'configured_voltage = cpu_to_le16(0);' \
        'configured_voltage = cpu_to_le16(1200);' \
        's#configured_voltage = cpu_to_le16(0);#configured_voltage = cpu_to_le16(1200);#'
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
main() {
    echo -e "${C_BOLD}anti-detection.sh v${SCRIPT_VERSION}${C_RESET}"
    echo -e "${C_DIM}QEMU VM-fingerprint suppression patch script${C_RESET}"
    echo ""

    parse_args "$@"
    detect_sed
    safety_checks
    run_patches
    print_summary
}

main "$@"

