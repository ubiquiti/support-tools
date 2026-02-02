#!/bin/bash

# Chip Firmware Upgrade Script for EA64
# This script upgrades disk controller firmware, PCIe switch firmware, and embedded controller firmware
# Designed to work with: curl -fsSL <url> | sudo bash

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_NAME="upgrade-chip-fw.sh"
readonly TMP_DIR="/tmp"
readonly LOG_FILE="/tmp/chip-firmware-upgrade.log"

# Target firmware versions
readonly DISK_CTRL_TARGET_VERSION="35.01.00.02"
readonly EMB_CTRL_TARGET_VERSION="v1A.01.02"
readonly PCIE_SW_TARGET_VERSION="24 08 21 20 c5 00"

# GitHub firmware URLs
readonly GITHUB_BASE_URL="https://github.com/ubiquiti/support-tools/raw/master/ea64/chip-firmware-upgrade/firmware"
readonly DISK_CTRL_FW_URL="$GITHUB_BASE_URL/disk-ctrl"
readonly PCIE_SW_FW_URL="$GITHUB_BASE_URL/pcie-switch"
readonly EMB_CTRL_FW_URL="$GITHUB_BASE_URL/emb-ctrl"

# Disk controller firmware configuration
readonly DISK_CTRL_TOOL="disk-ctrl-tool"
readonly DISK_CTRL_TOOL_MD5="2285a832c86dec82c79a513d4daf00d7"
readonly DISK_CTRL_BIN1="disk-ctrl-2port.bin"
readonly DISK_CTRL_BIN1_MD5="0e239f9fb3e31a24f10a9348e3f96e61"
readonly DISK_CTRL_BIN2="disk-ctrl-5port.bin"
readonly DISK_CTRL_BIN2_MD5="024b9a124a21807a4b8ac0d13be161bd"

# Embedded controller firmware configuration
readonly EMB_CTRL_BIN="emb-ctrl-firmware.bin"
readonly EMB_CTRL_BIN_MD5="9ec6d911637c2b4519d64f70b8790eff"
readonly EMB_CTRL_INSTALL_PATH="/lib/firmware/ui-ese-firmware.bin"

# PCIe switch firmware configuration
readonly PCIE_SW_TOOL="pcie-sw-tool"
readonly PCIE_SW_TOOL_MD5="997515ae01fad8bcfd51db4e57a83a97"
readonly PCIE_SW_TARGET_BIN="pcie-sw-firmware.bin"
readonly PCIE_SW_BIN_MD5="c963f84d250221ab2fe8f970c2793bf2"
readonly PCIE_SW_DEVICE_ID_1="812b"
readonly PCIE_SW_DEVICE_ID_2="2824"

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
DISK_CTRL_UPGRADE_NEEDED=false
EMB_CTRL_UPGRADE_NEEDED=false
PCIE_SW_UPGRADE_NEEDED=false
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

Chip Firmware Upgrade Script for EA64

This script upgrades chip firmware and embedded controller firmware on supported Ubiquiti devices.
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
    local disk_ctrl_version="${1:-35.01.00.02}"
    local emb_ctrl_version="${2:-v1A.01.01}"
    local pcie_sw_info="${3:-}"
    
    if [[ "${FORCE:-false}" == "true" ]]; then
        return 0
    fi
    
    echo
    echo "WARNING: This will upgrade chip firmware on your device."
    echo "System ID: $SYSTEM_ID"
    echo "Target disk controller firmware version: $disk_ctrl_version"
    echo "Target embedded controller firmware version: $emb_ctrl_version"
    [[ -n "$pcie_sw_info" ]] && echo "Target PCIe switch firmware: $pcie_sw_info"
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
# DISK CONTROLLER FIRMWARE UPGRADE FUNCTIONS
# ==============================================================================

disk_ctrl_download_files() {
    log_info "Downloading disk controller firmware files..."
    
    local files=(
        "$DISK_CTRL_TOOL"
        "$DISK_CTRL_BIN1" 
        "$DISK_CTRL_BIN2"
    )
    
    local file_idx=0
    for file in "${files[@]}"; do
        file_idx=$((file_idx + 1))
        local url="$DISK_CTRL_FW_URL/$file"
        local dest="$TMP_DIR/$file"
        
        log_info "Downloading disk controller firmware ($file_idx/${#files[@]})..."
        
        if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
            log_error "Failed to download disk controller firmware ($file_idx/${#files[@]})"
            return 1
        fi
        
        if [[ ! -f "$dest" ]]; then
            log_error "Downloaded firmware file does not exist"
            return 1
        fi
        
        local file_size
        file_size=$(stat -c%s "$dest" 2>/dev/null || echo "0")
        if [[ $file_size -eq 0 ]]; then
            log_error "Downloaded firmware file is empty"
            return 1
        fi
        
        log_info "Successfully downloaded firmware file ($file_idx/${#files[@]}, ${file_size} bytes)"
    done
    
    return 0
}

disk_ctrl_validate_files() {
    log_info "Validating disk controller firmware files..."
    
    local files_and_checksums=(
        "$DISK_CTRL_TOOL:$DISK_CTRL_TOOL_MD5"
        "$DISK_CTRL_BIN1:$DISK_CTRL_BIN1_MD5"
        "$DISK_CTRL_BIN2:$DISK_CTRL_BIN2_MD5"
    )
    
    local file_idx=0
    for file_info in "${files_and_checksums[@]}"; do
        file_idx=$((file_idx + 1))
        local filename="${file_info%:*}"
        local expected_md5="${file_info#*:}"
        local filepath="$TMP_DIR/$filename"
        
        if [[ ! -f "$filepath" ]]; then
            log_error "Firmware file $file_idx not found"
            return 1
        fi
        
        log_info "Verifying checksum for firmware file $file_idx..."
        local actual_md5
        actual_md5=$(md5sum "$filepath" | awk '{print $1}')
        
        if [[ "$actual_md5" != "$expected_md5" ]]; then
            log_error "Checksum mismatch for firmware file $file_idx"
            log_error "Expected: $expected_md5"
            log_error "Actual:   $actual_md5"
            return 1
        fi
        
        log_info "Checksum verified for firmware file $file_idx"
    done
    
    if ! chmod +x "$TMP_DIR/$DISK_CTRL_TOOL"; then
        log_error "Failed to make firmware tool executable"
        return 1
    fi
    
    if [[ ! -x "$TMP_DIR/$DISK_CTRL_TOOL" ]]; then
        log_error "Firmware tool is not executable"
        return 1
    fi
    
    log_info "All disk controller firmware files validated successfully"
    return 0
}

disk_ctrl_check_chip() {
    local index="$1"
    local chip_info
    
    log_info "Checking disk controller chip at index $index..." >&2
    
    if ! chip_info=$("$TMP_DIR/$DISK_CTRL_TOOL" /v "$index" 2>/dev/null); then
        log_info "No chip found at index $index, skipping" >&2
        return 1
    fi
    
    local version
    local pin48
    version=$(echo "$chip_info" | grep "Version:" | awk '{print $2}' || echo "")
    pin48=$(echo "$chip_info" | grep "48pin=" | sed 's/.*48pin=\([0-9]\).*/\1/' || echo "")
    
    if [[ -z "$version" ]]; then
        log_warn "Could not parse version from chip $index output" >&2
        return 1
    fi
    
    if [[ -z "$pin48" ]]; then
        log_warn "Could not parse pin config from chip $index output" >&2
        return 1
    fi
    
    log_info "Found disk controller at index $index: version=$version, type=$pin48" >&2
    
    echo "$version:$pin48"
    if [[ "$version" == "$DISK_CTRL_TARGET_VERSION" ]]; then
        log_info "Chip at index $index is already up to date (version $version)" >&2
    fi
    return 0
}

disk_ctrl_upgrade_chip() {
    local index="$1"
    local version="$2"
    local pin48="$3"
    local firmware_file
    local chip_type
    
    case "$pin48" in
        0)
            firmware_file="$DISK_CTRL_BIN2"
            chip_type="5-port"
            ;;
        1)
            firmware_file="$DISK_CTRL_BIN1" 
            chip_type="2-port"
            ;;
        *)
            log_error "Unknown chip type at index $index"
            return 1
            ;;
    esac
    
    log_info "Upgrading $chip_type disk controller at index $index (current version: $version)"
    
    local upgrade_log="$TMP_DIR/disk_ctrl_upgrade_${index}.log"
    
    if timeout 120 "$TMP_DIR/$DISK_CTRL_TOOL" /w "$TMP_DIR/$firmware_file" "$index" >"$upgrade_log" 2>&1; then
        log_info "Successfully upgraded disk controller at index $index"
        DISK_CTRL_UPGRADE_NEEDED=true
        return 0
    else
        local exit_code=$?
        log_error "Failed to upgrade disk controller at index $index (exit code: $exit_code)"
        
        if [[ -f "$upgrade_log" ]]; then
            log_error "Upgrade output:"
            while IFS= read -r line; do
                log_error "  $line"
            done < "$upgrade_log"
        fi
        
        return 1
    fi
}

disk_ctrl_run_firmware_update() {
    log_info "Starting disk controller firmware upgrade process..."
    
    local chips_checked=0
    local chips_upgraded=0
    local failed_upgrades=0
    
    for index in 1 2 3 4; do
        local chip_info
        
        chip_info=$(disk_ctrl_check_chip "$index") || true
        if [[ -n "$chip_info" ]]; then
            chips_checked=$((chips_checked + 1))
            local version="${chip_info%:*}"
            local pin48="${chip_info#*:}"
            if [[ "$version" != "$DISK_CTRL_TARGET_VERSION" ]]; then
                if disk_ctrl_upgrade_chip "$index" "$version" "$pin48"; then
                    chips_upgraded=$((chips_upgraded + 1))
                else
                    failed_upgrades=$((failed_upgrades + 1))
                fi
            fi
        fi
    done
    
    log_info "Disk controller firmware update summary:"
    log_info "  Chips checked: $chips_checked"
    log_info "  Chips upgraded: $chips_upgraded" 
    log_info "  Failed upgrades: $failed_upgrades"
    
    if [[ $failed_upgrades -gt 0 ]]; then
        log_error "Some disk controller upgrades failed"
        return 1
    fi
    
    if [[ $chips_upgraded -eq 0 ]]; then
        log_info "No disk controllers required upgrading"
    else
        log_info "All disk controller upgrades completed successfully"
    fi
    
    return 0
}

disk_ctrl_dry_run_check() {
    log_info "Disk controller dry run - checking chips..."
    
    for index in 1 2 3 4; do
        disk_ctrl_check_chip "$index" >/dev/null || true
    done
}

# ==============================================================================
# PCIe SWITCH FIRMWARE UPGRADE FUNCTIONS
# ==============================================================================

pcie_sw_normalize_version() {
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]'
}

pcie_sw_download_files() {
    log_info "Downloading PCIe switch firmware files..."

    local files=("$PCIE_SW_TOOL" "$PCIE_SW_TARGET_BIN")

    local file_idx=0
    for file in "${files[@]}"; do
        file_idx=$((file_idx + 1))
        local url="$PCIE_SW_FW_URL/$file"
        local dest="$TMP_DIR/$file"
        
        log_info "Downloading PCIe switch firmware ($file_idx/${#files[@]})..."
        
        if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
            log_error "Failed to download PCIe switch firmware ($file_idx/${#files[@]})"
            return 1
        fi
        
        if [[ ! -f "$dest" ]]; then
            log_error "Downloaded firmware file does not exist"
            return 1
        fi
        
        local file_size
        file_size=$(stat -c%s "$dest" 2>/dev/null || echo "0")
        if [[ $file_size -eq 0 ]]; then
            log_error "Downloaded firmware file is empty"
            return 1
        fi
        
        log_info "Successfully downloaded firmware file ($file_idx/${#files[@]}, ${file_size} bytes)"
    done

    if ! chmod +x "$TMP_DIR/$PCIE_SW_TOOL" 2>/dev/null; then
        log_error "Failed to make PCIe switch tool executable"
        return 1
    fi
    
    log_info "PCIe switch firmware files downloaded successfully"
    return 0
}

pcie_sw_validate_files() {
    log_info "Validating PCIe switch firmware files..."

    if [[ ! -f "$TMP_DIR/$PCIE_SW_TOOL" ]] || [[ ! -x "$TMP_DIR/$PCIE_SW_TOOL" ]]; then
        log_error "PCIe switch tool not found or not executable"
        return 1
    fi

    local actual_md5
    actual_md5=$(md5sum "$TMP_DIR/$PCIE_SW_TOOL" | awk '{print $1}')
    if [[ "$actual_md5" != "$PCIE_SW_TOOL_MD5" ]]; then
        log_error "Checksum mismatch for PCIe switch tool (expected $PCIE_SW_TOOL_MD5, got $actual_md5)"
        return 1
    fi

    if [[ ! -f "$TMP_DIR/$PCIE_SW_TARGET_BIN" ]]; then
        log_error "PCIe switch firmware not found"
        return 1
    fi
    actual_md5=$(md5sum "$TMP_DIR/$PCIE_SW_TARGET_BIN" | awk '{print $1}')
    if [[ "$actual_md5" != "$PCIE_SW_BIN_MD5" ]]; then
        log_error "Checksum mismatch for PCIe switch firmware (expected $PCIE_SW_BIN_MD5, got $actual_md5)"
        return 1
    fi

    log_info "All PCIe switch firmware files validated successfully"
    return 0
}

pcie_sw_get_switch_list() {
    local output
    if ! output=$("$TMP_DIR/$PCIE_SW_TOOL" /s 2>/dev/null); then
        log_warn "PCIe switch scan failed or no switches found"
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

pcie_sw_identify_chip() {
    local pci_addr="$1"
    local lspci_out
    lspci_out=$(lspci -s "$pci_addr" 2>/dev/null) || echo ""
    if [[ "$lspci_out" =~ Device\ ([0-9a-fA-F]+) ]]; then
        local dev_id="${BASH_REMATCH[1]}"
        case "$dev_id" in
            "$PCIE_SW_DEVICE_ID_1") echo "TYPE1" ;;
            "$PCIE_SW_DEVICE_ID_2") echo "TYPE2" ;;
            *) echo "UNKNOWN" ;;
        esac
    else
        echo "UNKNOWN"
    fi
}

pcie_sw_get_versions() {
    local output
    output=$("$TMP_DIR/$PCIE_SW_TOOL" -s 2>/dev/null) || echo ""
    local -A versions
    while IFS= read -r line; do
        if [[ "$line" =~ \[([0-9a-fA-F:\.]+)\]\ PCIe\ Switch\ ([0-9]+):\ (.+) ]]; then
            local pci="${BASH_REMATCH[1]}"
            local idx="${BASH_REMATCH[2]}"
            local ver="${BASH_REMATCH[3]}"
            ver="${ver#"${ver%%[![:space:]]*}"}"
            ver="${ver%"${ver##*[![:space:]]}"}"
            versions["$idx"]="$ver"
        fi
    done <<< "$output"
    for idx in $(echo "${!versions[@]}" | tr ' ' '\n' | sort -n); do
        echo "$idx:${versions[$idx]}"
    done
}

pcie_sw_upgrade_switch() {
    local switch_index="$1"
    local chip_model="$2"
    local current_version="${3:-}"
    local firmware_file=""
    local target_version=""

    case "$chip_model" in
        TYPE2)
            firmware_file="$PCIE_SW_TARGET_BIN"
            target_version="$PCIE_SW_TARGET_VERSION"
            ;;
        TYPE1)
            log_info "PCIe switch $switch_index firmware not available for this type, skipping"
            return 2
            ;;
        *)
            log_warn "Unknown PCIe switch at index $switch_index, skipping"
            return 2
            ;;
    esac

    if [[ -z "$firmware_file" ]]; then
        return 2
    fi

    if [[ "$chip_model" == "TYPE2" ]]; then
        local current_norm
        current_norm=$(pcie_sw_normalize_version "$current_version")
        local target_norm
        target_norm=$(pcie_sw_normalize_version "$target_version")
        if [[ "$current_norm" == "$target_norm" ]]; then
            log_info "PCIe switch $switch_index already up to date (version: $current_version)"
            return 2
        fi
    fi

    log_info "Upgrading PCIe switch $switch_index, current version: $current_version"

    local upgrade_log="$TMP_DIR/pcie_sw_upgrade_${switch_index}.log"
    if ( cd "$TMP_DIR" && timeout 120 "./$PCIE_SW_TOOL" /u "$firmware_file" /b "$switch_index" ) >"$upgrade_log" 2>&1; then
        if grep -q "Update SPI flash ROM......PASS" "$upgrade_log" && \
           grep -q "PASS : 1" "$upgrade_log" && ! grep -q "FAIL : [1-9]" "$upgrade_log"; then
            log_info "Successfully upgraded PCIe switch $switch_index"
            PCIE_SW_UPGRADE_NEEDED=true
            return 0
        fi
    fi

    log_error "Failed to upgrade PCIe switch $switch_index"
    if [[ -f "$upgrade_log" ]]; then
        while IFS= read -r line; do
            log_error "  $line"
        done < "$upgrade_log"
    fi
    return 1
}

pcie_sw_run_firmware_update() {
    log_info "Starting PCIe switch firmware upgrade process..."

    if ! pcie_sw_download_files; then
        log_warn "PCIe switch firmware download failed, skipping"
        return 0
    fi
    
    if ! pcie_sw_validate_files; then
        log_error "PCIe switch file validation failed"
        return 1
    fi

    local switch_list
    switch_list=$(pcie_sw_get_switch_list) || true
    if [[ -z "$switch_list" ]]; then
        log_info "No PCIe switches found, skipping"
        return 0
    fi

    local -A pci_map
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local idx="${entry%%:*}"
        local pci="${entry#*:}"
        pci_map[$idx]="$pci"
    done <<< "$switch_list"

    local -A version_map
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local idx="${entry%%:*}"
        local ver="${entry#*:}"
        version_map[$idx]="$ver"
    done <<< "$(pcie_sw_get_versions)"

    local upgraded=0
    local failed=0

    for entry in $switch_list; do
        [[ -z "$entry" ]] && continue
        local switch_index="${entry%%:*}"
        local pci_addr="${entry#*:}"
        local chip_model
        chip_model=$(pcie_sw_identify_chip "$pci_addr")
        local current_version="${version_map[$switch_index]:-}"

        log_info "PCIe switch $switch_index at $pci_addr (version: $current_version)"

        if [[ "$chip_model" == "UNKNOWN" ]]; then
            log_warn "Could not identify PCIe switch at $pci_addr, skipping"
            continue
        fi

        pcie_sw_upgrade_switch "$switch_index" "$chip_model" "$current_version"
        local ret=$?
        if [[ $ret -eq 0 ]]; then
            upgraded=$((upgraded + 1))
        elif [[ $ret -eq 1 ]]; then
            failed=$((failed + 1))
        fi
    done

    log_info "PCIe switch firmware update summary: upgraded=$upgraded, failed=$failed"
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

pcie_sw_dry_run_check() {
    log_info "PCIe switch dry run - identifying switches..."

    if ! pcie_sw_download_files; then
        return 0
    fi
    if ! pcie_sw_validate_files; then
        log_warn "PCIe switch validation failed, skipping dry run"
        return 0
    fi

    local switch_list
    switch_list=$(pcie_sw_get_switch_list) || true
    if [[ -z "$switch_list" ]]; then
        log_info "No PCIe switches found"
        return 0
    fi

    for entry in $switch_list; do
        [[ -z "$entry" ]] && continue
        local switch_index="${entry%%:*}"
        local pci_addr="${entry#*:}"
        local chip_model
        chip_model=$(pcie_sw_identify_chip "$pci_addr")
        log_info "  PCIe switch $switch_index at $pci_addr (type: $chip_model)"
    done
}

# ==============================================================================
# EMBEDDED CONTROLLER FIRMWARE DOWNLOAD AND INSTALL FUNCTIONS
# ==============================================================================

emb_ctrl_download_files() {
    log_info "Downloading embedded controller firmware..."

    local dest="$TMP_DIR/$EMB_CTRL_BIN"

    local url="$EMB_CTRL_FW_URL/$EMB_CTRL_BIN"

    if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
        log_error "Failed to download embedded controller firmware"
        return 1
    fi

    if [[ ! -f "$dest" ]]; then
        log_error "Downloaded firmware file does not exist"
        return 1
    fi

    local file_size
    file_size=$(stat -c%s "$dest" 2>/dev/null || echo "0")
    if [[ $file_size -eq 0 ]]; then
        log_error "Downloaded firmware file is empty"
        return 1
    fi

    log_info "Successfully downloaded embedded controller firmware (${file_size} bytes)"
    return 0
}

emb_ctrl_validate_files() {
    log_info "Validating embedded controller firmware..."

    local filepath="$TMP_DIR/$EMB_CTRL_BIN"

    if [[ ! -f "$filepath" ]]; then
        log_error "Embedded controller firmware not found"
        return 1
    fi

    local actual_md5
    actual_md5=$(md5sum "$filepath" | awk '{print $1}')

    if [[ "$actual_md5" != "$EMB_CTRL_BIN_MD5" ]]; then
        log_error "Checksum mismatch for embedded controller firmware (expected $EMB_CTRL_BIN_MD5, got $actual_md5)"
        return 1
    fi

    log_info "Embedded controller firmware checksum verified"
    return 0
}

emb_ctrl_install_firmware() {
    log_info "Installing embedded controller firmware..."

    local src="$TMP_DIR/$EMB_CTRL_BIN"

    if [[ -f "$EMB_CTRL_INSTALL_PATH" ]]; then
        local existing_md5
        existing_md5=$(md5sum "$EMB_CTRL_INSTALL_PATH" | awk '{print $1}')
        if [[ "$existing_md5" == "$EMB_CTRL_BIN_MD5" ]]; then
            log_info "Embedded controller firmware already up to date, skipping install"
            return 0
        fi
        log_info "Replacing existing embedded controller firmware"
    fi

    if ! cp -f "$src" "$EMB_CTRL_INSTALL_PATH"; then
        log_error "Failed to install embedded controller firmware"
        return 1
    fi

    local installed_md5
    installed_md5=$(md5sum "$EMB_CTRL_INSTALL_PATH" | awk '{print $1}')
    if [[ "$installed_md5" != "$EMB_CTRL_BIN_MD5" ]]; then
        log_error "Installed embedded controller firmware checksum mismatch"
        return 1
    fi

    log_info "Embedded controller firmware installed successfully"
    return 0
}

# ==============================================================================
# EMBEDDED CONTROLLER UPGRADE FUNCTIONS
# ==============================================================================

emb_ctrl_check_present() {
    local dev_id="$1"
    local present_file="/sys/devices/platform/ui-ese-${dev_id}/present"
    
    if [[ -f "$present_file" ]] && [[ $(cat "$present_file" 2>/dev/null) == "1" ]]; then
        return 0
    else
        return 1
    fi
}

emb_ctrl_get_version() {
    local dev_id="$1"
    local version_file="/sys/devices/platform/ui-ese-${dev_id}/version"
    
    if [[ -f "$version_file" ]]; then
        cat "$version_file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

emb_ctrl_version_to_decimal() {
    local version="$1"
    if [[ $version =~ ^v([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})$ ]]; then
        local major=$((16#${BASH_REMATCH[1]}))
        local minor=$((16#${BASH_REMATCH[2]}))
        local patch=$((16#${BASH_REMATCH[3]}))
        echo "$((major * 10000 + minor * 100 + patch))"
    else
        echo "0"
    fi
}

emb_ctrl_upgrade_device() {
    local dev_id="$1"
    local current_version="$2"
    local base_path="/sys/devices/platform/ui-ese-${dev_id}"
    
    log_info "Upgrading embedded controller $dev_id (current version: $current_version)..."
    
    log_info "Entering DFU mode for embedded controller $dev_id..."
    if ! echo 1 > "$base_path/dfu_or_reset" 2>/dev/null; then
        log_error "Failed to enter DFU mode for embedded controller $dev_id"
        return 1
    fi
    
    sleep 2
    
    local current_decimal
    current_decimal=$(emb_ctrl_version_to_decimal "$current_version")
    local threshold_decimal
    threshold_decimal=$(emb_ctrl_version_to_decimal "v19.04.00")
    
    local upgrade_type
    if [[ $current_decimal -lt $threshold_decimal ]]; then
        upgrade_type="all"
        log_info "Version $current_version < v19.04.00, performing full upgrade"
    else
        upgrade_type="app"
        log_info "Version $current_version >= v19.04.00, performing app upgrade only"
    fi
    
    log_info "Starting $upgrade_type upgrade for embedded controller $dev_id..."
    if ! echo "$upgrade_type" > "$base_path/upgrade" 2>/dev/null; then
        log_error "Failed to start upgrade for embedded controller $dev_id"
        echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
        return 1
    fi
    
    log_info "Monitoring upgrade progress for embedded controller $dev_id..."
    local progress=0
    local max_wait=300
    local wait_count=0
    
    while [[ $progress -lt 100 && $wait_count -lt $max_wait ]]; do
        local error_status
        if [[ -f "$base_path/upgrade_error" ]]; then
            error_status=$(cat "$base_path/upgrade_error" 2>/dev/null || echo "0")
            if [[ "$error_status" != "0" ]]; then
                log_error "Upgrade error detected for embedded controller $dev_id: $error_status"
                echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
                return 1
            fi
        fi
        
        if [[ -f "$base_path/upgrade_progress" ]]; then
            progress=$(cat "$base_path/upgrade_progress" 2>/dev/null || echo "0")
            if [[ $((wait_count % 10)) -eq 0 ]]; then
                log_info "Embedded controller $dev_id upgrade progress: ${progress}%"
            fi
        fi
        
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    if [[ $progress -lt 100 ]]; then
        log_error "Upgrade timeout for embedded controller $dev_id (progress: ${progress}%)"
        echo 0 > "$base_path/dfu_or_reset" 2>/dev/null || true
        return 1
    fi
    
    log_info "Embedded controller $dev_id upgrade completed (${progress}%)"
    
    sleep 1
    log_info "Exiting DFU mode for embedded controller $dev_id..."
    if ! echo 0 > "$base_path/dfu_or_reset" 2>/dev/null; then
        log_warn "Failed to exit DFU mode for embedded controller $dev_id"
    fi
    
    sleep 3
    
    local new_version
    new_version=$(emb_ctrl_get_version "$dev_id")
    if [[ -n "$new_version" ]]; then
        local new_decimal
        new_decimal=$(emb_ctrl_version_to_decimal "$new_version")
        local target_decimal
        target_decimal=$(emb_ctrl_version_to_decimal "$EMB_CTRL_TARGET_VERSION")
        
        if [[ $new_decimal -ge $target_decimal ]]; then
            log_info "Embedded controller $dev_id upgrade successful: $current_version -> $new_version"
            return 0
        else
            log_error "Embedded controller $dev_id upgrade verification failed: expected >= $EMB_CTRL_TARGET_VERSION, got $new_version"
            return 1
        fi
    else
        log_error "Could not verify embedded controller $dev_id version after upgrade"
        return 1
    fi
}

emb_ctrl_run_upgrade() {
    log_info "Starting embedded controller upgrade process..."
    
    local target_decimal
    target_decimal=$(emb_ctrl_version_to_decimal "$EMB_CTRL_TARGET_VERSION")
    
    local devices_present=0
    local devices_checked=0
    local devices_upgraded=0
    local failed_upgrades=0
    
    for dev_id in 1 2; do
        log_info "Checking embedded controller $dev_id..."
        
        if ! emb_ctrl_check_present "$dev_id"; then
            log_info "Embedded controller $dev_id is not present, skipping"
            continue
        fi
        
        devices_present=$((devices_present + 1))
        devices_checked=$((devices_checked + 1))
        log_info "Embedded controller $dev_id is present"
        
        local current_version
        current_version=$(emb_ctrl_get_version "$dev_id")
        
        if [[ -z "$current_version" ]]; then
            log_warn "Could not read version for embedded controller $dev_id, skipping"
            continue
        fi
        
        log_info "Embedded controller $dev_id current version: $current_version"
        
        local current_decimal
        current_decimal=$(emb_ctrl_version_to_decimal "$current_version")
        
        if [[ $current_decimal -ge $target_decimal ]]; then
            log_info "Embedded controller $dev_id is already up to date (>= $EMB_CTRL_TARGET_VERSION)"
            continue
        fi
        
        log_info "Embedded controller $dev_id needs upgrade: $current_version < $EMB_CTRL_TARGET_VERSION"
        
        if emb_ctrl_upgrade_device "$dev_id" "$current_version"; then
            devices_upgraded=$((devices_upgraded + 1))
            EMB_CTRL_UPGRADE_NEEDED=true
        else
            failed_upgrades=$((failed_upgrades + 1))
        fi
    done
    
    log_info "Embedded controller upgrade summary:"
    log_info "  Devices present: $devices_present"
    log_info "  Devices checked: $devices_checked"
    log_info "  Devices upgraded: $devices_upgraded"
    log_info "  Failed upgrades: $failed_upgrades"
    
    if [[ $failed_upgrades -gt 0 ]]; then
        log_error "Some embedded controller upgrades failed"
        return 1
    fi
    
    if [[ $devices_present -eq 0 ]]; then
        log_info "No embedded controllers are present on this system"
    elif [[ $devices_upgraded -eq 0 ]]; then
        log_info "No embedded controller upgrades were needed"
    else
        log_info "All embedded controller upgrades completed successfully"
    fi
    
    return 0
}

emb_ctrl_dry_run_check() {
    log_info "Embedded controller dry run - checking devices..."
    
    for dev_id in 1 2; do
        if emb_ctrl_check_present "$dev_id"; then
            local version
            version=$(emb_ctrl_get_version "$dev_id")
            log_info "Embedded controller $dev_id: present, version=$version"
        else
            log_info "Embedded controller $dev_id: not present"
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
    
    rm -f "$TMP_DIR/$DISK_CTRL_TOOL" "$TMP_DIR/$DISK_CTRL_BIN1" "$TMP_DIR/$DISK_CTRL_BIN2" 2>/dev/null || true
    rm -f "$TMP_DIR/$PCIE_SW_TOOL" "$TMP_DIR/$PCIE_SW_TARGET_BIN" 2>/dev/null || true
    rm -f "$TMP_DIR/$EMB_CTRL_BIN" 2>/dev/null || true
    
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
    log_info "Target disk controller firmware: $DISK_CTRL_TARGET_VERSION"
    log_info "Target PCIe switch firmware: $PCIE_SW_TARGET_VERSION"
    log_info "Target embedded controller firmware: $EMB_CTRL_TARGET_VERSION"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Validation phase
    log_info "=== Validation Phase ==="
    if ! validate_system; then
        log_error "System validation failed"
        exit 1
    fi
    
    log_info "=== Disk Controller Firmware Download & Validation ==="
    if ! disk_ctrl_download_files; then
        log_error "Disk controller firmware download failed"
        exit 1
    fi
    
    if ! disk_ctrl_validate_files; then
        log_error "Disk controller firmware validation failed"
        exit 1
    fi
    
    log_info "=== Embedded Controller Firmware Download & Validation ==="
    if ! emb_ctrl_download_files; then
        log_error "Embedded controller firmware download failed"
        exit 1
    fi
    
    if ! emb_ctrl_validate_files; then
        log_error "Embedded controller firmware validation failed"
        exit 1
    fi

    if ! emb_ctrl_install_firmware; then
        log_error "Embedded controller firmware installation failed"
        exit 1
    fi
    
    local pcie_sw_available=false
    log_info "=== PCIe Switch Firmware Download & Validation (Optional) ==="
    if pcie_sw_download_files && pcie_sw_validate_files; then
        pcie_sw_available=true
        log_info "PCIe switch firmware available for upgrade"
    else
        log_info "PCIe switch firmware not available, skipping"
    fi
    
    local pcie_sw_info="N/A (not available)"
    if [[ "$pcie_sw_available" == "true" ]]; then
        pcie_sw_info="$PCIE_SW_TARGET_BIN"
    fi
    confirm_upgrade "$DISK_CTRL_TARGET_VERSION" "$EMB_CTRL_TARGET_VERSION" "$pcie_sw_info"
    
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
        disk_ctrl_dry_run_check
        emb_ctrl_dry_run_check
        if [[ "$pcie_sw_available" == "true" ]]; then
            pcie_sw_dry_run_check
        fi
    else
        log_info "=== Disk Controller Firmware Upgrade ==="
        if ! disk_ctrl_run_firmware_update; then
            log_error "Disk controller firmware update failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
        
        if [[ "$DISK_CTRL_UPGRADE_NEEDED" == "true" ]]; then
            UPGRADE_NEEDED=true
        fi
        
        if [[ "$pcie_sw_available" == "true" ]]; then
            log_info "=== PCIe Switch Firmware Upgrade ==="
            if ! pcie_sw_run_firmware_update; then
                log_error "PCIe switch firmware upgrade failed"
                log_error "Please contact support for assistance"
                exit 1
            fi
            
            if [[ "$PCIE_SW_UPGRADE_NEEDED" == "true" ]]; then
                UPGRADE_NEEDED=true
            fi
        fi
        
        log_info "=== Embedded Controller Firmware Upgrade ==="
        if ! emb_ctrl_run_upgrade; then
            log_error "Embedded controller upgrade failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
        
        if [[ "$EMB_CTRL_UPGRADE_NEEDED" == "true" ]]; then
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
            echo -n "$i "
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
