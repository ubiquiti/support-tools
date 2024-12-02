#!/bin/bash

etherlight_dfu_tool_path="/usr/bin/mar_dfu16"
etherlight_dfu_tool_sha256=afccd24954f26d06159283e83630f7235ff75e7dbaa03d57ee499379699033bc

etherlight_fw_path="/lib/firmware/etherlight-firmware.bin"
etherlight_fw_md5=cf1aaa43c2a58cbcc700a840145f45b2
etherlight_fw_aprom_crc32="0x9b51cb28"

etherlight_cal_data_path="/lib/firmware/etherlight-cal-data.bin"
etherlight_cal_data_md5=7bd824c3c18c1ee2cde0501b3a1f97c1
etherlight_cal_data_crc32="0x2c4b3362"

sysid=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info)
rev=$(awk -F= 'match($1, /boardrevision/) {print $2}' /proc/ubnthal/system.info)

if [ "ea3f" != "$sysid" ] || [ "${rev:-0}" -lt "7" ]; then
    echo "Invalid product: $sysid($rev)"
    exit 1
fi

bezel_present=$(cat /sys/class/leds/etherlight/present)
if [ "$bezel_present" != "1" ]; then
    echo "Please install Bezel before this migration start"
    exit 1
fi

apt update -qq
apt install -y i2c-tools -qq
if [ $? -ne 0 ]; then
    echo "Cannot install i2c-tools, please check your internet connection"
    exit 1
fi

echo "Migrating Bezel, please do not remove it..."

upgrade_external_flash() {
    curl -sL -o $etherlight_cal_data_path "https://github.com/ubiquiti/support-tools/blob/master/envr/bezel-upgrade/etherlight-cal-data.bin?raw=true"
    if [ $? -ne 0 ]; then
        echo "Download external flash failed"
        exit 1
    fi

    md5sum -b $etherlight_cal_data_path | grep -qw $etherlight_cal_data_md5
    if [ $? -ne 0 ]; then
        echo "Checksum of external flash binary mismatch"
        exit 1
    fi

    echo 1 > /sys/class/leds/etherlight/cal_data_update
    if [ $? -ne 0 ]; then
        echo "Upgrade external flash failed"
        exit 1
    fi

    echo 1 > /sys/class/leds/etherlight/cold_reset
}


ext_flash_crc32=$(cat /sys/class/leds/etherlight/ext_flash_crc32)
if [ "$ext_flash_crc32" != "$etherlight_cal_data_crc32" ]; then
    echo "External flash CRC32 mismatch, upgrading..."
    upgrade_external_flash
fi
sleep 1

do_upgrade_etherlight_fw() {
    systemctl stop sfpd ulcmd

    i2cset -f -y 4 0x71 0x08
    i2cset -f -y 4 0x66 0x02 0x01
    sleep 3
    i2cset -f -y 4 0x66 0x00 0x00
    sleep 1
    i2cset -y -f 4 0x71 0x08
    i2cset -y -f 4 0x20 0x06 0xcd
    i2cset -y -f 4 0x20 0x02 0xcd
    i2cset -y -f 4 0x20 0x02 0xed
    sleep 1

    echo "update bezel firmware"

    chmod 755 $etherlight_dfu_tool_path
    $etherlight_dfu_tool_path 4 7 $etherlight_fw_path
    if [ $? -ne 0 ]; then
        echo "Upgrade failed"
        i2cset -y -f 4 0x20 0x02 0xcd
        i2cset -y -f 4 0x20 0x02 0xfd
        exit 1
    fi

    i2cset -y -f 4 0x20 0x02 0xcd
    i2cset -y -f 4 0x20 0x02 0xfd
    sleep 1

    echo 1 > /sys/class/leds/etherlight/boot_finish
    sleep 3
    echo 0 > /sys/class/leds/etherlight/led_mode
    sleep 1
    uled-ctrl fw idle

    systemctl start sfpd ulcmd
}

upgrade_etherlight_fw() {
    curl -sL -o $etherlight_dfu_tool_path "https://github.com/ubiquiti/support-tools/blob/master/envr/bezel-upgrade/mar_dfu16?raw=true"
    if [ $? -ne 0 ]; then
        echo "Download upgrade tool failed"
        exit 1
    fi

    sha256sum -b $etherlight_dfu_tool_path | grep -qw $etherlight_dfu_tool_sha256
    if [ $? -ne 0 ]; then
        echo "Checksum of upgrade tool mismatch"
        exit 1
    fi

    curl -sL -o $etherlight_fw_path "https://github.com/ubiquiti/support-tools/blob/master/envr/bezel-upgrade/etherlight-firmware.bin?raw=true"
    if [ $? -ne 0 ]; then
        echo "Download Bezel firmware failed"
        exit 1
    fi

    md5sum -b $etherlight_fw_path | grep -qw $etherlight_fw_md5
    if [ $? -ne 0 ]; then
        echo "Checksum of firmware mismatch"
        exit 1
    fi

    do_upgrade_etherlight_fw
}

aprom_crc32=$(cat /sys/class/leds/etherlight/aprom_crc32)
if [ "$aprom_crc32" != "$etherlight_fw_aprom_crc32" ]; then
    echo "Firmware CRC32 mismatch, upgrading..."
    upgrade_etherlight_fw
fi

aprom_crc32=$(cat /sys/class/leds/etherlight/aprom_crc32)
ext_flash_crc32=$(cat /sys/class/leds/etherlight/ext_flash_crc32)
if [ "$aprom_crc32" != "$etherlight_fw_aprom_crc32" ] || [ "$ext_flash_crc32" != "$etherlight_cal_data_crc32" ]; then
    echo "Validation failed, please try again"
    exit 1
fi

echo "Bezel migration completed. Suggest to reboot the device."
