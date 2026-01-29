#!/bin/bash

# Chip Firmware Upgrade Script for ENAS devices
# This script upgrades JMB582/JMB585 chip firmware on supported Ubiquiti devices

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

            log_info "version: $version"
            log_info "pin48: $pin48"
            
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

# Show usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Chip Firmware Upgrade Script for ENAS devices

This script upgrades JMB582/JMB585 chip firmware on supported Ubiquiti devices.
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
    - The upgrade process takes 1-2 minutes
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
    echo "WARNING: This will upgrade chip firmware on your device."
    echo "System ID: $SYSTEM_ID"
    echo "Target firmware version: $TARGET_VERSION"
    echo
    echo "The upgrade process:"
    echo "  - Takes 1-2 minutes to complete"
    echo "  - Will stop critical services temporarily"
    echo "  - Requires a reboot after completion"
    echo "  - MUST NOT be interrupted (do not power off)"
    echo
    
    read -p "Do you want to continue? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Upgrade cancelled by user"
        exit 0
    fi
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
    else
        if ! run_firmware_update; then
            log_error "Firmware update failed"
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
