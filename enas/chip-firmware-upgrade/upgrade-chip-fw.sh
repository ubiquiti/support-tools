#!/bin/bash

# File paths
TMP_DIR="/tmp"

# Tools and firmware files
# JMB58x
TOOL1="585upd"
TOOL1_MD5=2285a832c86dec82c79a513d4daf00d7

BIN1="JMB582B_STD_H35.01.00.02_20260109.bin"
BIN1_MD5=0e239f9fb3e31a24f10a9348e3f96e61

BIN2="JMB585B_STD_H35.01.00.02_20260109.bin"
BIN2_MD5=024b9a124a21807a4b8ac0d13be161bd

# Check system ID
sysid=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info)

# sanity checks
case "$sysid" in
ea64|da28)
    ;;
*)
    echo "Invalid product: $sysid"
    exit 1
    ;;
esac

CON_CORE=unifi-core.service
CON_DRIVE=unifi-drive.service
SRV_ULP_GO=ulp-go.service
SRV_UID_AGENT=uid-agent.service
FILE_SMBD=smbd.service
FILE_NFS_SERVER=nfs-server.service

# Download necessary files
download_files() {
    curl -sL -o $TMP_DIR/$TOOL1 "https://github.com/ubiquiti/support-tools/raw/master/enas/chip-firmware-upgrade/$TOOL1"
    curl -sL -o $TMP_DIR/$BIN1 "https://github.com/ubiquiti/support-tools/raw/master/enas/chip-firmware-upgrade/$BIN1"
    curl -sL -o $TMP_DIR/$BIN2 "https://github.com/ubiquiti/support-tools/raw/master/enas/chip-firmware-upgrade/$BIN2"
}

# Validate files and executability
check_files() {
    # echo "==> Checking required files..."

    # valid checksum and executable
    # Check JMB58x
    md5sum -b ${TMP_DIR}/${TOOL1} | grep -qw ${TOOL1_MD5}
    if [ $? -ne 0 ]; then
        echo " - ${TOOL1} checksum mismatch"
        return 1
    fi

    md5sum -b ${TMP_DIR}/${BIN1} | grep -qw ${BIN1_MD5}
    if [ $? -ne 0 ]; then
        echo " - ${BIN1} checksum mismatch"
        return 1
    fi

    md5sum -b ${TMP_DIR}/${BIN2} | grep -qw ${BIN2_MD5}
    if [ $? -ne 0 ]; then
        echo " - ${BIN2} checksum mismatch"
        return 1
    fi

    if [[ ! -x "${TMP_DIR}/${TOOL1}" ]]; then
        echo " - ${TOOL1} not executable"
        return 1
    fi

    return 0
}

# Stop controller and services
stop_services() {
    systemctl stop $FILE_NFS_SERVER $FILE_SMBD $CON_CORE $CON_DRIVE $SRV_ULP_GO $SRV_UID_AGENT 
}

# Run firmware update tools
run_firmware_update() {
    echo "==> Checking chip firmware versions..."
    
    # Check each chip index (1-4)
    for index in 1 2 3 4; do
        echo "Checking chip index $index..."
        
        # Get chip information
        chip_info=$($TMP_DIR/$TOOL1 /v $index 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            echo "  No chip found at index $index, skipping..."
            continue
        fi
        
        # Parse version and 48pin from output
        version=$(echo "$chip_info" | grep "Version:" | awk '{print $2}')
        pin48=$(echo "$chip_info" | grep "48pin=" | sed 's/.*48pin=\([0-9]\).*/\1/')
        
        # echo "  Found chip: Version=$version, 48pin=$pin48"
        
        # Check if version is already up to date
        if [ "$version" = "35.01.00.02" ]; then
            echo "  Chip at index $index is already up to date"
            continue
        fi
        
        # Determine which firmware to use based on 48pin value
        if [ "$pin48" = "0" ]; then
            # JMB585 chip - use BIN2
            firmware_file="$BIN2"
            chip_type="JMB585"
        elif [ "$pin48" = "1" ]; then
            # JMB582 chip - use BIN1
            firmware_file="$BIN1"
            chip_type="JMB582"
        else
            echo "  Unknown chip type (48pin=$pin48) at index $index, skipping..."
            continue
        fi
        
        echo "  Upgrading $chip_type chip..."
        
        # Run firmware upgrade
        if $TMP_DIR/$TOOL1 /w $TMP_DIR/$firmware_file $index >/dev/null 2>&1; then
            echo "  Successfully upgraded chip at index $index"
        else
            echo "  Failed to upgrade chip at index $index"
            return 1
        fi
    done
    
    echo "==> Chip firmware upgrade process completed"
    return 0
}

echo "==> Prepare chip firmware upgrade process..."

if ! download_files; then
    exit 1
fi

if ! check_files; then
    exit 1
fi

echo "==> Starting chip firmware upgrade process..."
echo "    It takes about 1~2 minutes. Please be patient."
echo "    PLEASE DO NOT TURN OFF THE DEVICE."

echo "==> Stopping services..."

stop_services
sync; sync; sync

if ! run_firmware_update; then
    echo "Firmware update FAILED."
    echo "Please contact support for help."
    exit 1
fi

echo "==> Firmware update completed successfully"
echo "==> Please reboot the device to apply the new firmware."
