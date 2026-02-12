#!/bin/bash

# Chip and ESE Firmware Upgrade Script for ENAS devices (Standalone Version)
# This script upgrades JMB582/JMB585 chip firmware, ASM28xx PCIe switches, and ESE firmware
# Designed to work with: curl -fsSL <url> | sudo bash

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_NAME="upgrade-chip-fw.sh"
readonly TMP_DIR="/tmp"
readonly LOG_FILE="/tmp/chip-firmware-upgrade.log"

# Target firmware versions
readonly JMB58X_TARGET_VERSION="35.01.00.02"
readonly ESE_TARGET_VERSION="v1A.01.01"
readonly ASM2824_TARGET_VERSION="24 08 21 20 c5 00"

# GitHub firmware URLs
readonly GITHUB_BASE_URL="https://github.com/ubiquiti/support-tools/raw/master/enas/chip-firmware-upgrade/firmware"
readonly JMB58X_FIRMWARE_URL="$GITHUB_BASE_URL/jmb58x"
readonly ASM28XX_FIRMWARE_URL="$GITHUB_BASE_URL/asm2824"

# JMB58x firmware configuration
readonly JMB58X_TOOL="585upd"
readonly JMB58X_TOOL_MD5="2285a832c86dec82c79a513d4daf00d7"
readonly JMB58X_BIN1="JMB582B_STD_H35.01.00.02_20260109.bin"
readonly JMB58X_BIN1_MD5="0e239f9fb3e31a24f10a9348e3f96e61"
readonly JMB58X_BIN2="JMB585B_STD_H35.01.00.02_20260109.bin"
readonly JMB58X_BIN2_MD5="024b9a124a21807a4b8ac0d13be161bd"

# ASM28xx firmware configuration
readonly ASM28XX_TOOL="28xxfwdl"
readonly ASM28XX_TOOL_MD5="997515ae01fad8bcfd51db4e57a83a97"
readonly ASM2824_TARGET_BIN="240821_20_C5_00.bin"
readonly ASM2824_BIN_MD5="c963f84d250221ab2fe8f970c2793bf2"
readonly ASM2812_DEVICE_ID="812b"
readonly ASM2824_DEVICE_ID="2824"

# Services to manage during upgrade
readonly SERVICES=(
    "nfs-server.service"
    "smbd.service" 
    "unifi-core.service"
    "unifi-drive.service"
    "ulp-go.service"
    "uid-agent.service"
)

# Global variables
SYSTEM_ID=""
UPGRADE_NEEDED=false
JMB58X_UPGRADE_NEEDED=false
ESE_UPGRADE_NEEDED=false
ASM28XX_UPGRADE_NEEDED=false
DRY_RUN=false
FORCE=false

# Initialize logging
init_logging() {
    : > "$LOG_FILE"  # Clear log file
    echo "[INFO] Starting $SCRIPT_NAME at $(date)" | tee -a "$LOG_FILE"
    echo "[INFO] PID: $$" | tee -a "$LOG_FILE"
}

# Logging functions
log_info() {
    local message="$1"
    echo "[INFO] $message" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="$1"
    echo "[WARN] $message" | tee -a "$LOG_FILE" >&2
}

log_error() {
    local message="$1"
    echo "[ERROR] $message" | tee -a "$LOG_FILE" >&2
}

# ==============================================================================
# COMMON UTILITY FUNCTIONS
# ==============================================================================

# System validation functions
validate_system() {
    log_info "Validating system compatibility..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        return 1
    fi
    
    # Check system ID
    if [[ ! -f /proc/ubnthal/system.info ]]; then
        log_error "System info file not found. This script is for Ubiquiti devices only."
        return 1
    fi
    
    # Export SYSTEM_ID so it's available to other modules
    export SYSTEM_ID=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info 2>/dev/null || echo "")
    
    if [[ -z "$SYSTEM_ID" ]]; then
        log_error "Could not determine system ID"
        return 1
    fi
    
    case "$SYSTEM_ID" in
        ea64|da28)
            log_info "System ID: $SYSTEM_ID (supported)"
            ;;
        *)
            log_error "Unsupported system ID: $SYSTEM_ID"
            log_error "This script only supports: ea64, da28"
            return 1
            ;;
    esac
    
    # Check available disk space (need at least 10MB)
    local available_space
    available_space=$(df "$TMP_DIR" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 10240 ]]; then
        log_error "Insufficient disk space in $TMP_DIR (need at least 10MB)"
        return 1
    fi
    
    return 0
}

# Service management functions
stop_services() {
    log_info "Stopping services to prevent interference during firmware update..."
    
    local failed_services=()
    
    for service in "${SERVICES[@]}"; do
        log_info "Stopping $service..."
        
        # Check if service exists and is active
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            if systemctl stop "$service" 2>/dev/null; then
                log_info "Successfully stopped $service"
            else
                log_warn "Failed to stop $service"
                failed_services+=("$service")
            fi
        else
            log_info "$service is not active, skipping"
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_warn "Some services failed to stop: ${failed_services[*]}"
        log_warn "Continuing with firmware update..."
    fi
    
    # Sync filesystem
    log_info "Syncing filesystem..."
    sync; sync; sync
    
    return 0
}

start_services() {
    log_info "Starting services..."
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "Starting $service..."
            if systemctl start "$service" 2>/dev/null; then
                log_info "Successfully started $service"
            else
                log_warn "Failed to start $service"
            fi
        fi
    done
}

# Show usage information
show_usage() {
    local script_name="${1:-firmware-upgrade}"
    cat << EOF
Usage: $script_name [OPTIONS]

Chip and ESE Firmware Upgrade Script for ENAS devices

This script upgrades JMB582/JMB585 chip firmware and ESE firmware on supported Ubiquiti devices.
Supported devices: ea64, da28

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    --dry-run       Check devices but don't perform upgrades
    --force         Skip confirmation prompts

EXAMPLES:
    $script_name                    # Normal upgrade
    $script_name --dry-run          # Check only, no upgrades
    $script_name --verbose          # Verbose output

NOTES:
    - This script must be run as root
    - The upgrade process takes 3-5 minutes
    - DO NOT power off the device during upgrade
    - A reboot is required after successful upgrade

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage "$SCRIPT_NAME"
                exit 0
                ;;
            -v|--verbose)
                set -x  # Enable verbose mode
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage "$SCRIPT_NAME"
                exit 1
                ;;
        esac
    done
}

# Confirmation prompt
confirm_upgrade() {
    local jmb58x_version="${1:-35.01.00.02}"
    local ese_version="${2:-v1A.01.01}"
    local asm28xx_info="${3:-}"
    
    if [[ "${FORCE:-false}" == "true" ]]; then
        return 0
    fi
    
    echo
    echo "WARNING: This will upgrade chip and ESE firmware on your device."
    echo "System ID: $SYSTEM_ID"
    echo "Target JMB58x chip firmware version: $jmb58x_version"
    echo "Target ESE firmware version: $ese_version"
    [[ -n "$asm28xx_info" ]] && echo "Target ASM28xx PCIe switch firmware: $asm28xx_info"
    echo
    echo "The upgrade process:"
    echo "  - Takes 1-2 minutes to complete"
    echo "  - Will stop critical services temporarily"
    echo "  - Requires a reboot after completion"
    echo "  - MUST NOT be interrupted (do not power off)"
    echo
    
    echo "Starting upgrade in 5 seconds... (Press Ctrl+C to cancel)"
    for i in 5 4 3 2 1; do
        echo -n "$i... "
        sleep 1
    done
    echo
    echo "Starting upgrade now!"
}

# ==============================================================================
# JMB58X FIRMWARE UPGRADE FUNCTIONS
# ==============================================================================

# Download JMB58x firmware files directly (standalone version)
jmb58x_download_files() {
    log_info "Downloading JMB58x firmware files..."
    
    local files=(
        "$JMB58X_TOOL"
        "$JMB58X_BIN1" 
        "$JMB58X_BIN2"
    )
    
    for file in "${files[@]}"; do
        local url="$JMB58X_FIRMWARE_URL/$file"
        local dest="$TMP_DIR/$file"
        
        log_info "Downloading $file..."
        
        if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
            log_error "Failed to download $file from $url"
            return 1
        fi
        
        if [[ ! -f "$dest" ]]; then
            log_error "Downloaded file $dest does not exist"
            return 1
        fi
        
        local file_size
        file_size=$(stat -c%s "$dest" 2>/dev/null || echo "0")
        if [[ $file_size -eq 0 ]]; then
            log_error "Downloaded file $dest is empty"
            return 1
        fi
        
        log_info "Successfully downloaded $file (${file_size} bytes)"
    done
    
    return 0
}

# Validate JMB58x firmware files
jmb58x_validate_files() {
    log_info "Validating JMB58x firmware files..."
    
    local files_and_checksums=(
        "$JMB58X_TOOL:$JMB58X_TOOL_MD5"
        "$JMB58X_BIN1:$JMB58X_BIN1_MD5"
        "$JMB58X_BIN2:$JMB58X_BIN2_MD5"
    )
    
    for file_info in "${files_and_checksums[@]}"; do
        local filename="${file_info%:*}"
        local expected_md5="${file_info#*:}"
        local filepath="$TMP_DIR/$filename"
        
        # Check if file exists
        if [[ ! -f "$filepath" ]]; then
            log_error "File not found: $filepath"
            return 1
        fi
        
        # Verify checksum
        log_info "Verifying checksum for $filename..."
        local actual_md5
        actual_md5=$(md5sum "$filepath" | awk '{print $1}')
        
        if [[ "$actual_md5" != "$expected_md5" ]]; then
            log_error "Checksum mismatch for $filename"
            log_error "Expected: $expected_md5"
            log_error "Actual:   $actual_md5"
            return 1
        fi
        
        log_info "Checksum verified for $filename"
    done
    
    # Make tool executable
    if ! chmod +x "$TMP_DIR/$JMB58X_TOOL"; then
        log_error "Failed to make $JMB58X_TOOL executable"
        return 1
    fi
    
    # Verify tool is executable
    if [[ ! -x "$TMP_DIR/$JMB58X_TOOL" ]]; then
        log_error "$JMB58X_TOOL is not executable"
        return 1
    fi
    
    log_info "All JMB58x files validated successfully"
    return 0
}

# Check individual chip version and type
jmb58x_check_chip() {
    local index="$1"
    local chip_info
    
    log_info "Checking JMB58x chip at index $index..." >&2
    
    # Get chip information
    if ! chip_info=$("$TMP_DIR/$JMB58X_TOOL" /v "$index" 2>/dev/null); then
        log_info "No chip found at index $index, skipping" >&2
        return 1
    fi
    
    # Parse version and 48pin from output
    local version
    local pin48
    version=$(echo "$chip_info" | grep "Version:" | awk '{print $2}' || echo "")
    pin48=$(echo "$chip_info" | grep "48pin=" | sed 's/.*48pin=\([0-9]\).*/\1/' || echo "")
    
    if [[ -z "$version" ]]; then
        log_warn "Could not parse version from chip $index output" >&2
        return 1
    fi
    
    if [[ -z "$pin48" ]]; then
        log_warn "Could not parse 48pin value from chip $index output" >&2
        return 1
    fi
    
    log_info "Found JMB58x chip at index $index: Version=$version, 48pin=$pin48" >&2
    
    # Check if version is already up to date
    if [[ "$version" == "$JMB58X_TARGET_VERSION" ]]; then
        log_info "Chip at index $index is already up to date (version $version)" >&2
        return 1
    fi
    
    # Return only the clean data to stdout
    echo "$version:$pin48"
    return 0
}

# Upgrade individual chip
jmb58x_upgrade_chip() {
    local index="$1"
    local version="$2"
    local pin48="$3"
    local firmware_file
    local chip_type
    
    # Determine which firmware to use based on 48pin value
    case "$pin48" in
        0)
            firmware_file="$JMB58X_BIN2"
            chip_type="JMB585"
            ;;
        1)
            firmware_file="$JMB58X_BIN1" 
            chip_type="JMB582"
            ;;
        *)
            log_error "Unknown chip type (48pin=$pin48) at index $index"
            return 1
            ;;
    esac
    
    log_info "Upgrading $chip_type chip at index $index (current version: $version)"
    log_info "Using firmware file: $firmware_file"
    
    # Create temporary log file for this upgrade
    local upgrade_log="$TMP_DIR/jmb58x_upgrade_${index}.log"
    
    # Run firmware upgrade with timeout
    if timeout 120 "$TMP_DIR/$JMB58X_TOOL" /w "$TMP_DIR/$firmware_file" "$index" >"$upgrade_log" 2>&1; then
        log_info "Successfully upgraded JMB58x chip at index $index"
        JMB58X_UPGRADE_NEEDED=true
        return 0
    else
        local exit_code=$?
        log_error "Failed to upgrade JMB58x chip at index $index (exit code: $exit_code)"
        
        # Log the upgrade output for debugging
        if [[ -f "$upgrade_log" ]]; then
            log_error "Upgrade output:"
            while IFS= read -r line; do
                log_error "  $line"
            done < "$upgrade_log"
        fi
        
        return 1
    fi
}

# Main JMB58x firmware update function
jmb58x_run_firmware_update() {
    log_info "Starting JMB58x chip firmware upgrade process..."
    
    local chips_checked=0
    local chips_upgraded=0
    local failed_upgrades=0
    
    # Check each chip index (1-4)
    for index in 1 2 3 4; do
        local chip_info
        
        if chip_info=$(jmb58x_check_chip "$index"); then
            chips_checked=$((chips_checked + 1))
            
            # Parse chip info
            local version="${chip_info%:*}"
            local pin48="${chip_info#*:}"
            
            if jmb58x_upgrade_chip "$index" "$version" "$pin48"; then
                chips_upgraded=$((chips_upgraded + 1))
            else
                failed_upgrades=$((failed_upgrades + 1))
            fi
        fi
    done
    
    log_info "JMB58x firmware update summary:"
    log_info "  Chips checked: $chips_checked"
    log_info "  Chips upgraded: $chips_upgraded" 
    log_info "  Failed upgrades: $failed_upgrades"
    
    if [[ $failed_upgrades -gt 0 ]]; then
        log_error "Some JMB58x chip upgrades failed"
        return 1
    fi
    
    if [[ $chips_upgraded -eq 0 ]]; then
        log_info "No JMB58x chips required upgrading"
    else
        log_info "All JMB58x chip upgrades completed successfully"
    fi
    
    return 0
}

# Dry run check for JMB58x chips
jmb58x_dry_run_check() {
    log_info "JMB58x dry run - checking chips..."
    
    for index in 1 2 3 4; do
        jmb58x_check_chip "$index" >/dev/null || true
    done
}

# ==============================================================================
# ASM28XX PCIe SWITCH FIRMWARE UPGRADE FUNCTIONS
# ==============================================================================

# Normalize version string from "24 08 21 20 c5 00" to "24082120c500" for comparison
asm28xx_normalize_version() {
    local v="$1"
    echo "$v" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]'
}

# Download ASM28xx firmware files directly (standalone version)
asm28xx_download_files() {
    log_info "Downloading ASM28xx firmware files..."

    local files=("$ASM28XX_TOOL" "$ASM2824_TARGET_BIN")

    for file in "${files[@]}"; do
        local url="$ASM28XX_FIRMWARE_URL/$file"
        local dest="$TMP_DIR/$file"
        
        log_info "Downloading $file from GitHub..."
        
        if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
            log_error "Failed to download $file from $url"
            return 1
        fi
        
        if [[ ! -f "$dest" ]]; then
            log_error "Downloaded file $dest does not exist"
            return 1
        fi
        
        local file_size
        file_size=$(stat -c%s "$dest" 2>/dev/null || echo "0")
        if [[ $file_size -eq 0 ]]; then
            log_error "Downloaded file $dest is empty"
            return 1
        fi
        
        log_info "Successfully downloaded $file (${file_size} bytes)"
    done

    # Make tool executable
    if ! chmod +x "$TMP_DIR/$ASM28XX_TOOL" 2>/dev/null; then
        log_error "Failed to make $ASM28XX_TOOL executable"
        return 1
    fi
    
    log_info "ASM28xx firmware files downloaded successfully"
    return 0
}

# Validate ASM28xx firmware files (existence and checksum where we have MD5)
asm28xx_validate_files() {
    log_info "Validating ASM28xx firmware files..."

    if [[ ! -f "$TMP_DIR/$ASM28XX_TOOL" ]] || [[ ! -x "$TMP_DIR/$ASM28XX_TOOL" ]]; then
        log_error "Tool not found or not executable: $TMP_DIR/$ASM28XX_TOOL"
        return 1
    fi

    local actual_md5
    actual_md5=$(md5sum "$TMP_DIR/$ASM28XX_TOOL" | awk '{print $1}')
    if [[ "$actual_md5" != "$ASM28XX_TOOL_MD5" ]]; then
        log_error "Checksum mismatch for $ASM28XX_TOOL (expected $ASM28XX_TOOL_MD5, got $actual_md5)"
        return 1
    fi

    if [[ ! -f "$TMP_DIR/$ASM2824_TARGET_BIN" ]]; then
        log_error "ASM2824 firmware not found: $ASM2824_TARGET_BIN"
        return 1
    fi
    actual_md5=$(md5sum "$TMP_DIR/$ASM2824_TARGET_BIN" | awk '{print $1}')
    if [[ "$actual_md5" != "$ASM2824_BIN_MD5" ]]; then
        log_error "Checksum mismatch for $ASM2824_TARGET_BIN (expected $ASM2824_BIN_MD5, got $actual_md5)"
        return 1
    fi

    log_info "All ASM28xx files validated successfully"
    return 0
}

# Run 28xxfwdl /s and parse output to get switch index -> PCI address mapping
asm28xx_get_switch_list() {
    local output
    if ! output=$("$TMP_DIR/$ASM28XX_TOOL" /s 2>/dev/null); then
        log_warn "28xxfwdl /s failed or no ASMedia PCIe switches found"
        return 1
    fi
    local count=0
    while IFS= read -r line; do
        if [[ "$line" =~ \[([0-9a-fA-F:\.]+)\]\ PCIe\ Switch\ ([0-9]+): ]]; then
            echo "${BASH_REMATCH[2]}:${BASH_REMATCH[1]}"
            count=$((count + 1))
        fi
    done <<< "$output"
    [[ $count -eq 0 ]] && return 1
    return 0
}

# Identify chip model (ASM2812 or ASM2824) from PCI address using lspci
asm28xx_identify_chip() {
    local pci_addr="$1"
    local lspci_out
    lspci_out=$(lspci -s "$pci_addr" 2>/dev/null) || echo ""
    if [[ "$lspci_out" =~ Device\ ([0-9a-fA-F]+) ]]; then
        local dev_id="${BASH_REMATCH[1]}"
        case "$dev_id" in
            "$ASM2812_DEVICE_ID") echo "ASM2812" ;;
            "$ASM2824_DEVICE_ID") echo "ASM2824" ;;
            *) echo "UNKNOWN" ;;
        esac
    else
        echo "UNKNOWN"
    fi
}

# Get current version string for all switches from 28xxfwdl -s
asm28xx_get_versions() {
    local output
    output=$("$TMP_DIR/$ASM28XX_TOOL" -s 2>/dev/null) || echo ""
    local -A versions
    while IFS= read -r line; do
        if [[ "$line" =~ \[([0-9a-fA-F:\.]+)\]\ PCIe\ Switch\ ([0-9]+):\ (.+) ]]; then
            local pci="${BASH_REMATCH[1]}"
            local idx="${BASH_REMATCH[2]}"
            local ver="${BASH_REMATCH[3]}"
            versions["$idx"]="$ver"
        fi
    done <<< "$output"
    # Print switch_index:version (one per line) so caller can loop
    for idx in $(echo "${!versions[@]}" | tr ' ' '\n' | sort -n); do
        echo "$idx:${versions[$idx]}"
    done
}

# Check if a switch needs upgrade and perform it
asm28xx_upgrade_switch() {
    local switch_index="$1"
    local chip_model="$2"
    local current_version="${3:-}"
    local firmware_file=""
    local target_version=""

    case "$chip_model" in
        ASM2824)
            firmware_file="$ASM2824_TARGET_BIN"
            target_version="$ASM2824_TARGET_VERSION"
            ;;
        ASM2812)
            log_info "ASM2812 firmware not available, skipping switch $switch_index"
            return 0
            ;;
        *)
            log_warn "Unknown chip at switch $switch_index, skipping"
            return 0
            ;;
    esac

    if [[ -z "$firmware_file" ]]; then
        return 0
    fi

    # For ASM2824: compare normalized version
    if [[ "$chip_model" == "ASM2824" ]]; then
        local current_norm
        current_norm=$(asm28xx_normalize_version "$current_version")
        local target_norm
        target_norm=$(asm28xx_normalize_version "$target_version")
        if [[ "$current_norm" == "$target_norm" ]]; then
            log_info "PCIe Switch $switch_index ($chip_model) already up to date (version: $current_version)"
            return 0
        fi
    fi

    log_info "Upgrading PCIe Switch $switch_index ($chip_model), current version: $current_version"
    log_info "Using firmware: $firmware_file"

    local upgrade_log="$TMP_DIR/asm28xx_upgrade_${switch_index}.log"
    if timeout 120 "$TMP_DIR/$ASM28XX_TOOL" /u "$TMP_DIR/$firmware_file" /b "$switch_index" >"$upgrade_log" 2>&1; then
        if grep -q "Update SPI flash ROM......PASS" "$upgrade_log" && \
           grep -q "PASS : 1" "$upgrade_log" && ! grep -q "FAIL : [1-9]" "$upgrade_log"; then
            log_info "Successfully upgraded PCIe Switch $switch_index ($chip_model)"
            ASM28XX_UPGRADE_NEEDED=true
            return 0
        fi
    fi

    log_error "Failed to upgrade PCIe Switch $switch_index ($chip_model)"
    if [[ -f "$upgrade_log" ]]; then
        while IFS= read -r line; do
            log_error "  $line"
        done < "$upgrade_log"
    fi
    return 1
}

# Main ASM28xx firmware update function
asm28xx_run_firmware_update() {
    log_info "Starting ASM28xx PCIe switch firmware upgrade process..."

    if ! asm28xx_download_files; then
        log_warn "ASM28xx firmware download failed, skipping ASM28xx upgrade"
        return 0
    fi
    
    if ! asm28xx_validate_files; then
        log_error "ASM28xx file validation failed"
        return 1
    fi

    local switch_list
    switch_list=$(asm28xx_get_switch_list) || true
    if [[ -z "$switch_list" ]]; then
        log_info "No ASMedia PCIe switches found, skipping ASM28xx upgrade"
        return 0
    fi

    # Build switch index -> PCI address map
    local -A pci_map
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local idx="${entry%%:*}"
        local pci="${entry#*:}"
        pci_map[$idx]="$pci"
    done <<< "$switch_list"

    # Get current versions (switch index -> version string)
    local -A version_map
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local idx="${entry%%:*}"
        local ver="${entry#*:}"
        version_map[$idx]="$ver"
    done <<< "$(asm28xx_get_versions)"

    local upgraded=0
    local failed=0

    for entry in $switch_list; do
        [[ -z "$entry" ]] && continue
        local switch_index="${entry%%:*}"
        local pci_addr="${entry#*:}"
        local chip_model
        chip_model=$(asm28xx_identify_chip "$pci_addr")
        local current_version="${version_map[$switch_index]:-}"

        log_info "PCIe Switch $switch_index: $pci_addr -> $chip_model (version: $current_version)"

        if [[ "$chip_model" == "UNKNOWN" ]]; then
            log_warn "Could not identify chip at $pci_addr, skipping"
            continue
        fi

        if asm28xx_upgrade_switch "$switch_index" "$chip_model" "$current_version"; then
            upgraded=$((upgraded + 1))
        else
            failed=$((failed + 1))
        fi
    done

    log_info "ASM28xx firmware update summary: upgraded=$upgraded, failed=$failed"
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Dry run: list switches and identify chips, no upgrade
asm28xx_dry_run_check() {
    log_info "ASM28xx dry run - identifying PCIe switches..."

    if ! asm28xx_download_files; then
        return 0
    fi
    if ! asm28xx_validate_files; then
        log_warn "ASM28xx validation failed, skipping dry run"
        return 0
    fi

    local switch_list
    switch_list=$(asm28xx_get_switch_list) || true
    if [[ -z "$switch_list" ]]; then
        log_info "No ASMedia PCIe switches found"
        return 0
    fi

    for entry in $switch_list; do
        [[ -z "$entry" ]] && continue
        local switch_index="${entry%%:*}"
        local pci_addr="${entry#*:}"
        local chip_model
        chip_model=$(asm28xx_identify_chip "$pci_addr")
        log_info "  PCIe Switch $switch_index: $pci_addr -> $chip_model"
    done
}

# ==============================================================================
# ESE FIRMWARE UPGRADE FUNCTIONS
# ==============================================================================

# Check if ESE is present
ese_check_present() {
    local ese_id="$1"
    local present_file="/sys/devices/platform/ui-ese-${ese_id}/present"
    
    if [[ -f "$present_file" ]] && [[ $(cat "$present_file" 2>/dev/null) == "1" ]]; then
        return 0
    else
        return 1
    fi
}

# Get ESE version
ese_get_version() {
    local ese_id="$1"
    local version_file="/sys/devices/platform/ui-ese-${ese_id}/version"
    
    if [[ -f "$version_file" ]]; then
        cat "$version_file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Convert hex version to decimal for comparison
ese_version_to_decimal() {
    local version="$1"
    # Extract vXX.XX.XX format and convert hex to decimal
    if [[ $version =~ ^v([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})$ ]]; then
        local major=$((16#${BASH_REMATCH[1]}))
        local minor=$((16#${BASH_REMATCH[2]}))
        local patch=$((16#${BASH_REMATCH[3]}))
        echo "$((major * 10000 + minor * 100 + patch))"
    else
        echo "0"
    fi
}

# Upgrade individual ESE
ese_upgrade_device() {
    local ese_id="$1"
    local current_version="$2"
    local base_path="/sys/devices/platform/ui-ese-${ese_id}"
    
    log_info "Upgrading ESE $ese_id (current version: $current_version)..."
    
    # Step 1: Enter DFU mode
    log_info "Entering DFU mode for ESE $ese_id..."
    if ! echo 1 > "$base_path/dfu_or_reset" 2>/dev/null; then
        log_error "Failed to enter DFU mode for ESE $ese_id"
        return 1
    fi
    
    # Wait a moment for DFU mode to be ready
    sleep 2
    
    # Step 2: Determine upgrade type based on version
    local current_decimal
    current_decimal=$(ese_version_to_decimal "$current_version")
    local threshold_decimal
    threshold_decimal=$(ese_version_to_decimal "v19.04.00")  # 0x190400 = 1639424
    
    local upgrade_type
    if [[ $current_decimal -lt $threshold_decimal ]]; then
        upgrade_type="all"
        log_info "Version $current_version < v19.04.00, performing full upgrade"
    else
        upgrade_type="app"
        log_info "Version $current_version >= v19.04.00, performing app upgrade only"
    fi
    
    # Step 3: Start upgrade
    log_info "Starting $upgrade_type upgrade for ESE $ese_id..."
    if ! echo "$upgrade_type" > "$base_path/upgrade" 2>/dev/null; then
        log_error "Failed to start upgrade for ESE $ese_id"
        # Try to exit DFU mode
        echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
        return 1
    fi
    
    # Step 4: Monitor upgrade progress
    log_info "Monitoring upgrade progress for ESE $ese_id..."
    local progress=0
    local max_wait=300  # 5 minutes timeout
    local wait_count=0
    
    while [[ $progress -lt 100 && $wait_count -lt $max_wait ]]; do
        # Check for upgrade error
        local error_status
        if [[ -f "$base_path/upgrade_error" ]]; then
            error_status=$(cat "$base_path/upgrade_error" 2>/dev/null || echo "0")
            if [[ "$error_status" != "0" ]]; then
                log_error "Upgrade error detected for ESE $ese_id: $error_status"
                echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
                return 1
            fi
        fi
        
        # Check progress
        if [[ -f "$base_path/upgrade_progress" ]]; then
            progress=$(cat "$base_path/upgrade_progress" 2>/dev/null || echo "0")
            if [[ $((wait_count % 10)) -eq 0 ]]; then  # Log every 10 seconds
                log_info "ESE $ese_id upgrade progress: ${progress}%"
            fi
        fi
        
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    if [[ $progress -lt 100 ]]; then
        log_error "Upgrade timeout for ESE $ese_id (progress: ${progress}%)"
        echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
        return 1
    fi
    
    log_info "ESE $ese_id upgrade completed (${progress}%)"
    
    # Step 5: Wait and exit DFU mode
    sleep 1
    log_info "Exiting DFU mode for ESE $ese_id..."
    if ! echo 0 > "$base_path/dfu_or_reset" 2>/dev/null; then
        log_warn "Failed to exit DFU mode for ESE $ese_id"
    fi
    
    # Wait for device to be ready
    sleep 3
    
    # Step 6: Verify upgrade
    local new_version
    new_version=$(ese_get_version "$ese_id")
    if [[ -n "$new_version" ]]; then
        local new_decimal
        new_decimal=$(ese_version_to_decimal "$new_version")
        local target_decimal
        target_decimal=$(ese_version_to_decimal "$ESE_TARGET_VERSION")  # 0x1A0101 = 1704193
        
        if [[ $new_decimal -ge $target_decimal ]]; then
            log_info "ESE $ese_id upgrade successful: $current_version -> $new_version"
            return 0
        else
            log_error "ESE $ese_id upgrade verification failed: expected >= $ESE_TARGET_VERSION, got $new_version"
            return 1
        fi
    else
        log_error "Could not verify ESE $ese_id version after upgrade"
        return 1
    fi
}

# Main ESE upgrade function
ese_run_upgrade() {
    log_info "Starting ESE upgrade process..."
    
    local target_decimal
    target_decimal=$(ese_version_to_decimal "$ESE_TARGET_VERSION")
    
    local eses_present=0
    local eses_checked=0
    local eses_upgraded=0
    local failed_upgrades=0
    
    # Check both ESE devices (1 and 2)
    for ese_id in 1 2; do
        log_info "Checking ESE $ese_id..."
        
        # Check if ESE is present
        if ! ese_check_present "$ese_id"; then
            log_info "ESE $ese_id is not present, skipping"
            continue
        fi
        
        eses_present=$((eses_present + 1))
        eses_checked=$((eses_checked + 1))
        log_info "ESE $ese_id is present"
        
        # Get current version
        local current_version
        current_version=$(ese_get_version "$ese_id")
        
        if [[ -z "$current_version" ]]; then
            log_warn "Could not read version for ESE $ese_id, skipping"
            continue
        fi
        
        log_info "ESE $ese_id current version: $current_version"
        
        # Check if upgrade is needed
        local current_decimal
        current_decimal=$(ese_version_to_decimal "$current_version")
        
        if [[ $current_decimal -ge $target_decimal ]]; then
            log_info "ESE $ese_id is already up to date (>= $ESE_TARGET_VERSION)"
            continue
        fi
        
        log_info "ESE $ese_id needs upgrade: $current_version < $ESE_TARGET_VERSION"
        
        # Perform upgrade
        if ese_upgrade_device "$ese_id" "$current_version"; then
            eses_upgraded=$((eses_upgraded + 1))
            ESE_UPGRADE_NEEDED=true
        else
            failed_upgrades=$((failed_upgrades + 1))
        fi
    done
    
    log_info "ESE upgrade summary:"
    log_info "  ESEs present: $eses_present"
    log_info "  ESEs checked: $eses_checked"
    log_info "  ESEs upgraded: $eses_upgraded"
    log_info "  Failed upgrades: $failed_upgrades"
    
    if [[ $failed_upgrades -gt 0 ]]; then
        log_error "Some ESE upgrades failed"
        return 1
    fi
    
    if [[ $eses_present -eq 0 ]]; then
        log_info "No ESE devices are present on this system"
    elif [[ $eses_upgraded -eq 0 ]]; then
        log_info "No ESE upgrades were needed"
    else
        log_info "All ESE upgrades completed successfully"
    fi
    
    return 0
}

# Dry run check for ESE devices
ese_dry_run_check() {
    log_info "ESE dry run - checking devices..."
    
    for ese_id in 1 2; do
        if ese_check_present "$ese_id"; then
            local version
            version=$(ese_get_version "$ese_id")
            log_info "ESE $ese_id: present, version=$version"
        else
            log_info "ESE $ese_id: not present"
        fi
    done
}

# ==============================================================================
# CLEANUP AND MAIN FUNCTIONS
# ==============================================================================

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script failed with exit code $exit_code"
        log_info "Check log file: $LOG_FILE"
    fi
    
    # Clean up JMB58x firmware files
    rm -f "$TMP_DIR/$JMB58X_TOOL" "$TMP_DIR/$JMB58X_BIN1" "$TMP_DIR/$JMB58X_BIN2" 2>/dev/null || true
    
    # Clean up ASM28xx firmware files
    rm -f "$TMP_DIR/$ASM28XX_TOOL" "$TMP_DIR/$ASM2824_TARGET_BIN" 2>/dev/null || true
    
    # Clean up upgrade logs
    rm -f "$TMP_DIR"/*_upgrade_*.log 2>/dev/null || true
}

# Set up cleanup trap
trap cleanup EXIT

# Main execution function
main() {
    local start_time
    start_time=$(date +%s)
    
    # Initialize
    init_logging
    
    log_info "=== Chip Firmware Upgrade Script ==="
    log_info "Script: $SCRIPT_NAME"
    log_info "Version: 2.0"
    log_info "Target JMB58x firmware: $JMB58X_TARGET_VERSION"
    log_info "Target ASM28xx firmware: ASM2824 $ASM2824_TARGET_VERSION"
    log_info "Target ESE firmware: $ESE_TARGET_VERSION"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Validation phase
    log_info "=== Validation Phase ==="
    if ! validate_system; then
        log_error "System validation failed"
        exit 1
    fi
    
    # Download and validate JMB58x firmware (required)
    log_info "=== JMB58x Firmware Download & Validation ==="
    if ! jmb58x_download_files; then
        log_error "JMB58x firmware download failed"
        exit 1
    fi
    
    if ! jmb58x_validate_files; then
        log_error "JMB58x firmware validation failed"
        exit 1
    fi
    
    # Try to download and validate ASM28xx firmware (optional)
    local asm28xx_available=false
    log_info "=== ASM28xx Firmware Download & Validation (Optional) ==="
    if asm28xx_download_files && asm28xx_validate_files; then
        asm28xx_available=true
        log_info "ASM28xx firmware available for upgrade"
    else
        log_info "ASM28xx firmware not available, skipping ASM28xx upgrade"
    fi
    
    # Confirmation
    local asm28xx_info="N/A (not available)"
    if [[ "$asm28xx_available" == "true" ]]; then
        asm28xx_info="ASM2824: $ASM2824_TARGET_BIN"
    fi
    confirm_upgrade "$JMB58X_TARGET_VERSION" "$ESE_TARGET_VERSION" "$asm28xx_info"
    
    # Service management phase
    log_info "=== Service Management Phase ==="
    if ! stop_services; then
        log_error "Failed to stop services"
        exit 1
    fi
    
    # Upgrade phase
    log_info "=== Firmware Upgrade Phase ==="
    log_info "Starting firmware upgrade process..."
    log_info "This may take 1-2 minutes. Please be patient."
    log_info "DO NOT POWER OFF THE DEVICE!"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "DRY RUN MODE - No actual upgrades will be performed"
        jmb58x_dry_run_check
        ese_dry_run_check
        if [[ "$asm28xx_available" == "true" ]]; then
            asm28xx_dry_run_check
        fi
    else
        # Run JMB58x chip firmware upgrade
        log_info "=== JMB58x Chip Firmware Upgrade ==="
        if ! jmb58x_run_firmware_update; then
            log_error "JMB58x chip firmware update failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
        
        if [[ "$JMB58X_UPGRADE_NEEDED" == "true" ]]; then
            UPGRADE_NEEDED=true
        fi
        
        # Run ASM28xx upgrade if available
        if [[ "$asm28xx_available" == "true" ]]; then
            log_info "=== ASM28xx PCIe Switch Upgrade ==="
            if ! asm28xx_run_firmware_update; then
                log_error "ASM28xx PCIe switch upgrade failed"
                log_error "Please contact support for assistance"
                exit 1
            fi
            
            if [[ "$ASM28XX_UPGRADE_NEEDED" == "true" ]]; then
                UPGRADE_NEEDED=true
            fi
        fi
        
        # Run ESE upgrade
        log_info "=== ESE Firmware Upgrade ==="
        if ! ese_run_upgrade; then
            log_error "ESE upgrade failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
        
        if [[ "$ESE_UPGRADE_NEEDED" == "true" ]]; then
            UPGRADE_NEEDED=true
        fi
    fi
    
    # Start services back up
    start_services
    
    # Completion
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "=== Completion ==="
    log_info "Script completed successfully in ${duration} seconds"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "DRY RUN completed - no changes were made"
    elif [[ "$UPGRADE_NEEDED" == "true" ]]; then
        log_info "Firmware upgrade completed successfully"
        echo
        echo "=== FIRMWARE UPGRADE COMPLETED ==="
        echo "The firmware upgrade completed successfully."
        echo "The device will reboot automatically in 10 seconds to apply the changes."
        echo
        echo "Press Ctrl+C to cancel automatic reboot..."
        
        # 10-second countdown
        for i in 10 9 8 7 6 5 4 3 2 1; do
            echo -n "Rebooting in $i seconds... "
            sleep 1
        done
        
        echo
        log_info "Initiating automatic reboot to apply firmware changes..."
        echo "Rebooting now!"
        
        # Execute reboot
        if ubnt-systool reboot; then
            log_info "Reboot command executed successfully"
        else
            log_error "Failed to execute reboot command"
            echo "Please manually reboot the device: ubnt-systool reboot"
        fi
    else
        log_info "No firmware upgrades were needed"
    fi
}

# Script entry point
# Handle both direct execution and piped execution (curl | bash)
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]] || [[ -z "${BASH_SOURCE[0]:-}" ]]; then
    main "$@"
fi
