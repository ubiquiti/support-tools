#!/bin/bash

# File paths
TMP_DIR="/tmp"

# Tools and firmware files
# RTS5315
TOOL1="rts_firmware_update_tool"
TOOL1_MD5=1e52a7e8a7a076d8b88db95a9ec196cb

BIN1="RTS5315_v0301_CRDAE_1786_20250605.bin"
BIN1_MD5=961b855b94a8523c90c78dddb5a922fd

# ASM3042
TOOL2="114xfwdl"
TOOL2_MD5=244155b25a2355e45d13285cd219692e

BIN2="240322_71_F8_59.bin"
BIN2_MD5=09cdeaf92926e90af35d278758619148

# Check system ID
sysid=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info)

# sanity checks
case "$sysid" in
ea51 | ea63 | ea67)
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
    curl -sL -o $TMP_DIR/$TOOL1 "https://github.com/ubiquiti/support-tools/raw/master/unas-pro/firmware/rts5315/$TOOL1"
    curl -sL -o $TMP_DIR/$BIN1 "https://github.com/ubiquiti/support-tools/raw/master/unas-pro/firmware/rts5315/$BIN1"
    curl -sL -o $TMP_DIR/$TOOL2 "https://github.com/ubiquiti/support-tools/raw/master/unas-pro/firmware/asm3042/$TOOL2"
    curl -sL -o $TMP_DIR/$BIN2 "https://github.com/ubiquiti/support-tools/raw/master/unas-pro/firmware/asm3042/$BIN2"

    chmod 755 $TMP_DIR/$TOOL1
    chmod 755 $TMP_DIR/$TOOL2
}

# Validate files and executability
check_files() {
    # echo "==> Checking required files..."

    # valid checksum and executable
    # Check RTS5315
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

    if [[ ! -x "${TMP_DIR}/${TOOL1}" ]]; then
        echo " - ${TOOL1} not executable"
        return 1
    fi

    # Check ASM3042
    md5sum -b ${TMP_DIR}/${TOOL2} | grep -qw ${TOOL2_MD5}
    if [ $? -ne 0 ]; then
        echo " - ${TOOL2} checksum mismatch"
        return 1
    fi

    md5sum -b ${TMP_DIR}/${BIN2} | grep -qw ${BIN2_MD5}
    if [ $? -ne 0 ]; then
        echo " - ${BIN2} checksum mismatch"
        return 1
    fi

    if [[ ! -x "${TMP_DIR}/${TOOL2}" ]]; then
        echo " - ${TOOL2} not executable"
        return 1
    fi

    return 0
}

# Run firmware update tools
run_firmware_update() {
    # Step 1: Update RTS5315 firmware
    echo "==> Updating RTS5315 firmware..."
    "${TMP_DIR}/${TOOL1}" boot "${TMP_DIR}/${BIN1}" >/dev/null 2>&1 || {
        echo "Failed to update RTS5315 firmware"
        return 1
    }
    sleep 0.5

    # Step 2: Update ASM3042 firmware
    echo "==> Updating ASM3042 firmware..."
    "${TMP_DIR}/${TOOL2}" -U "${TMP_DIR}/${BIN2}"  >/dev/null 2>&1 || {
        echo "Failed to update ASM3042 firmware"
        return 1
    }
    sleep 0.5

    return 0
}

# Stop controller and services
stop_services() {
    systemctl stop $FILE_NFS_SERVER $FILE_SMBD $CON_CORE $CON_DRIVE $SRV_ULP_GO $SRV_UID_AGENT 
}

# Reboot system
reboot_system() {
    sleep 1
    echo b > /proc/sysrq-trigger
}

echo "==> Prepare chip firmware upgrade process..."

if ! download_files; then
    exit 1
fi

if ! check_files; then
    exit 1
fi

echo "==> Starting chip firmware upgrade process..."
echo "    It takes about 10s ~ 20s. Please be patient."
echo "    PLEASE DO NOT TURN OFF THE DEVICE."

# echo "==> Stopping services..."

stop_services
sync; sync; sync

if ! run_firmware_update; then
    echo "Firmware update FAILED. System will not reboot."
    echo "Please contact support for help."
    exit 1
fi

echo "==> Firmware update completed successfully"
echo "==> Rebooting system..."

reboot_system
