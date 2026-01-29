#!/bin/bash

# Chip and ESE Firmware Upgrade Script for ENAS devices
# This script upgrades JMB582/JMB585 chip firmware and ESE firmware on supported Ubiquiti devices

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TMP_DIR="/tmp"
readonly LOG_FILE="/tmp/chip-firmware-upgrade.log"

# Target firmware version
readonly TARGET_VERSION="35.01.00.02"

# Tools and firmware files
readonly TOOL1="585upd"
readonly TOOL1_MD5="2285a832c86dec82c79a513d4daf00d7"

readonly BIN1="JMB582B_STD_H35.01.00.02_20260109.bin"  # JMB582 firmware
readonly BIN1_MD5="0e239f9fb3e31a24f10a9348e3f96e61"

readonly BIN2="JMB585B_STD_H35.01.00.02_20260109.bin"  # JMB585 firmware
readonly BIN2_MD5="024b9a124a21807a4b8ac0d13be161bd"

# GitHub base URL for downloads
readonly GITHUB_BASE_URL="https://github.com/ubiquiti/support-tools/raw/master/enas/chip-firmware-upgrade"

# Service names
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

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script failed with exit code $exit_code"
        log_info "Check log file: $LOG_FILE"
    fi
    
    # Clean up temporary files
    rm -f "$TMP_DIR/$TOOL1" "$TMP_DIR/$BIN1" "$TMP_DIR/$BIN2" 2>/dev/null || true
}

# Set up cleanup trap
trap cleanup EXIT

# Initialize logging
init_logging() {
    : > "$LOG_FILE"  # Clear log file
    log_info "Starting $SCRIPT_NAME at $(date)"
    log_info "PID: $$"
}

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
    
    SYSTEM_ID=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info 2>/dev/null || echo "")
    
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

# Download necessary files with proper error handling
download_files() {
    log_info "Downloading required files..."
    
    local files=(
        "$TOOL1"
        "$BIN1" 
        "$BIN2"
    )
    
    for file in "${files[@]}"; do
        local url="$GITHUB_BASE_URL/$file"
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

# Validate downloaded files
validate_files() {
    log_info "Validating downloaded files..."
    
    local files_and_checksums=(
        "$TOOL1:$TOOL1_MD5"
        "$BIN1:$BIN1_MD5"
        "$BIN2:$BIN2_MD5"
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
    if ! chmod +x "$TMP_DIR/$TOOL1"; then
        log_error "Failed to make $TOOL1 executable"
        return 1
    fi
    
    # Verify tool is executable
    if [[ ! -x "$TMP_DIR/$TOOL1" ]]; then
        log_error "$TOOL1 is not executable"
        return 1
    fi
    
    log_info "All files validated successfully"
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

# Check individual chip version and type
check_chip() {
    local index="$1"
    local chip_info
    
    log_info "Checking chip at index $index..." >&2
    
    # Get chip information
    if ! chip_info=$("$TMP_DIR/$TOOL1" /v "$index" 2>/dev/null); then
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
    
    log_info "Found chip at index $index: Version=$version, 48pin=$pin48" >&2
    
    # Check if version is already up to date
    if [[ "$version" == "$TARGET_VERSION" ]]; then
        log_info "Chip at index $index is already up to date (version $version)" >&2
        return 1
    fi
    
    # Return only the clean data to stdout
    echo "$version:$pin48"
    return 0
}

# Upgrade individual chip
upgrade_chip() {
    local index="$1"
    local version="$2"
    local pin48="$3"
    local firmware_file
    local chip_type
    
    # Determine which firmware to use based on 48pin value
    case "$pin48" in
        0)
            firmware_file="$BIN2"
            chip_type="JMB585"
            ;;
        1)
            firmware_file="$BIN1" 
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
    local upgrade_log="$TMP_DIR/upgrade_${index}.log"
    
    # Run firmware upgrade with timeout
    if timeout 120 "$TMP_DIR/$TOOL1" /w "$TMP_DIR/$firmware_file" "$index" >"$upgrade_log" 2>&1; then
        log_info "Successfully upgraded chip at index $index"
        UPGRADE_NEEDED=true
        return 0
    else
        local exit_code=$?
        log_error "Failed to upgrade chip at index $index (exit code: $exit_code)"
        
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

# Main firmware update function
run_firmware_update() {
    log_info "Starting chip firmware upgrade process..."
    
    local chips_checked=0
    local chips_upgraded=0
    local failed_upgrades=0
    
    # Check each chip index (1-4)
    for index in 1 2 3 4; do
        local chip_info
        
        if chip_info=$(check_chip "$index"); then
            chips_checked=$((chips_checked + 1))
            
            # Parse chip info
            local version="${chip_info%:*}"
            local pin48="${chip_info#*:}"
            
            if upgrade_chip "$index" "$version" "$pin48"; then
                chips_upgraded=$((chips_upgraded + 1))
            else
                failed_upgrades=$((failed_upgrades + 1))
            fi
        fi
    done
    
    log_info "Firmware update summary:"
    log_info "  Chips checked: $chips_checked"
    log_info "  Chips upgraded: $chips_upgraded" 
    log_info "  Failed upgrades: $failed_upgrades"
    
    if [[ $failed_upgrades -gt 0 ]]; then
        log_error "Some chip upgrades failed"
        return 1
    fi
    
    if [[ $chips_upgraded -eq 0 ]]; then
        log_info "No chips required upgrading"
    else
        log_info "All chip upgrades completed successfully"
    fi
    
    return 0
}

# ESE upgrade functions
check_ese_present() {
    local ese_id="$1"
    local present_file="/sys/devices/platform/ui-ese-${ese_id}/present"
    
    if [[ -f "$present_file" ]] && [[ $(cat "$present_file" 2>/dev/null) == "1" ]]; then
        return 0
    else
        return 1
    fi
}

get_ese_version() {
    local ese_id="$1"
    local version_file="/sys/devices/platform/ui-ese-${ese_id}/version"
    
    if [[ -f "$version_file" ]]; then
        cat "$version_file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Convert hex version to decimal for comparison
version_to_decimal() {
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

upgrade_ese() {
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
    current_decimal=$(version_to_decimal "$current_version")
    local threshold_decimal
    threshold_decimal=$(version_to_decimal "v19.04.00")  # 0x190400 = 1639424
    
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
    new_version=$(get_ese_version "$ese_id")
    if [[ -n "$new_version" ]]; then
        local new_decimal
        new_decimal=$(version_to_decimal "$new_version")
        local target_decimal
        target_decimal=$(version_to_decimal "v1A.01.01")  # 0x1A0101 = 1704193
        
        if [[ $new_decimal -ge $target_decimal ]]; then
            log_info "ESE $ese_id upgrade successful: $current_version -> $new_version"
            return 0
        else
            log_error "ESE $ese_id upgrade verification failed: expected >= v1A.01.01, got $new_version"
            return 1
        fi
    else
        log_error "Could not verify ESE $ese_id version after upgrade"
        return 1
    fi
}

run_ese_upgrade() {
    log_info "Starting ESE upgrade process..."
    
    local target_version="v1A.01.01"
    local target_decimal
    target_decimal=$(version_to_decimal "$target_version")
    
    local eses_present=0
    local eses_checked=0
    local eses_upgraded=0
    local failed_upgrades=0
    
    # Check both ESE devices (1 and 2)
    for ese_id in 1 2; do
        log_info "Checking ESE $ese_id..."
        
        # Check if ESE is present
        if ! check_ese_present "$ese_id"; then
            log_info "ESE $ese_id is not present, skipping"
            continue
        fi
        
        eses_present=$((eses_present + 1))
        eses_checked=$((eses_checked + 1))
        log_info "ESE $ese_id is present"
        
        # Get current version
        local current_version
        current_version=$(get_ese_version "$ese_id")
        
        if [[ -z "$current_version" ]]; then
            log_warn "Could not read version for ESE $ese_id, skipping"
            continue
        fi
        
        log_info "ESE $ese_id current version: $current_version"
        
        # Check if upgrade is needed
        local current_decimal
        current_decimal=$(version_to_decimal "$current_version")
        
        if [[ $current_decimal -ge $target_decimal ]]; then
            log_info "ESE $ese_id is already up to date (>= $target_version)"
            continue
        fi
        
        log_info "ESE $ese_id needs upgrade: $current_version < $target_version"
        
        # Perform upgrade
        if upgrade_ese "$ese_id" "$current_version"; then
            eses_upgraded=$((eses_upgraded + 1))
            UPGRADE_NEEDED=true
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

# Show usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Chip and ESE Firmware Upgrade Script for ENAS devices

This script upgrades JMB582/JMB585 chip firmware and ESE firmware on supported Ubiquiti devices.
Supported devices: ea64, da28

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    --dry-run       Check chips but don't perform upgrades
    --force         Skip confirmation prompts

EXAMPLES:
    $SCRIPT_NAME                    # Normal upgrade
    $SCRIPT_NAME --dry-run          # Check only, no upgrades
    $SCRIPT_NAME --verbose          # Verbose output

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
                show_usage
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
                show_usage
                exit 1
                ;;
        esac
    done
}

# Confirmation prompt
confirm_upgrade() {
    if [[ "${FORCE:-false}" == "true" ]]; then
        return 0
    fi
    
    echo
    echo "WARNING: This will upgrade chip and ESE firmware on your device."
    echo "System ID: $SYSTEM_ID"
    echo "Target chip firmware version: $TARGET_VERSION"
    echo "Target ESE firmware version: v1A.01.01"
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

# Main execution function
main() {
    local start_time
    start_time=$(date +%s)
    
    # Initialize
    init_logging
    parse_arguments "$@"
    
    log_info "=== Chip Firmware Upgrade Script ==="
    log_info "Script: $SCRIPT_NAME"
    log_info "Version: 2.0"
    log_info "Target firmware: $TARGET_VERSION"
    
    # Validation phase
    log_info "=== Validation Phase ==="
    if ! validate_system; then
        log_error "System validation failed"
        exit 1
    fi
    
    # Download phase  
    log_info "=== Download Phase ==="
    if ! download_files; then
        log_error "File download failed"
        exit 1
    fi
    
    if ! validate_files; then
        log_error "File validation failed"
        exit 1
    fi
    
    # Confirmation
    confirm_upgrade
    
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
        # Still run check functions but skip actual upgrades
        for index in 1 2 3 4; do
            check_chip "$index" >/dev/null || true
        done
        # Check ESE devices in dry run mode
        for ese_id in 1 2; do
            if check_ese_present "$ese_id"; then
                local version
                version=$(get_ese_version "$ese_id")
                log_info "ESE $ese_id: present, version=$version"
            else
                log_info "ESE $ese_id: not present"
            fi
        done
    else
        # Run chip firmware upgrade
        if ! run_firmware_update; then
            log_error "Chip firmware update failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
        
        # Run ESE upgrade
        log_info "=== ESE Upgrade Phase ==="
        if ! run_ese_upgrade; then
            log_error "ESE upgrade failed"
            log_error "Please contact support for assistance"
            exit 1
        fi
    fi
    
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
        log_info "IMPORTANT: Please reboot the device to apply the new firmware"
        echo
        echo "=== REBOOT REQUIRED ==="
        echo "The firmware upgrade completed successfully."
        echo "You MUST reboot the device now to apply the changes."
        echo
        echo "Run: ubnt-systool reboot"
    else
        log_info "No firmware upgrades were needed"
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
