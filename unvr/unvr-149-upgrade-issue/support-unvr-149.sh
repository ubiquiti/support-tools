#!/bin/bash

uboot_dev=$(grep '"u-boot"' /proc/mtd | cut -d: -f1 | sed 's/mtd/\/dev\/mtdblock/g')
uboot_env=$(grep '"u-boot env"' /proc/mtd | cut -d: -f1 | sed 's/mtd/\/dev\/mtdblock/g')
uboot_env_r=$(grep '"u-boot env redundant"' /proc/mtd | cut -d: -f1 | sed 's/mtd/\/dev\/mtdblock/g')
boot_img=/tmp/boot.img
boot_img_md5=009e4f87263c956f7ba012ccd2c4312e
sysid=$(ubnt-tools id | grep sysid)
sysid=${sysid#board.sysid=0x}

# sanity checks
case "$sysid" in
ea16|ea1a|ea20)
	;;
*)
	echo "Not support on this product ($sysid)."
	exit 1
	;;
esac

if ! grep -q al324\\.v1\\.4\\.9 /usr/lib/version; then
	echo "Not support on this fw version ($(cat /usr/lib/version))."
	exit 1
fi

if [ -z "$uboot_dev" ] || [ -z "$uboot_env" ] || [ -z "$uboot_env_r" ]; then
	echo "Some uboot devices are not found."
	exit 1
fi

curl -sL -o $boot_img \
	https://github.com/ubiquiti/support-tools/blob/master/unvr/unvr-149-upgrade-issue/boot.img?raw=true >/dev/null 2>&1

trap "rm -f $boot_img" EXIT

if ! (md5sum $boot_img | grep -q $boot_img_md5); then
	echo "md5sum mismatch ($(md5sum $boot_img))."
	exit 1
fi

boot_img_size=$(stat $boot_img -c%s)
if dd if=$uboot_dev iflag=count_bytes count=$boot_img_size 2>/dev/null | md5sum | grep -q $boot_img_md5; then
	echo "bootloader already up to date"
	exit 0
fi

echo "Updating bootloader."
echo "It takes about 30s ~ 60s. Please be patient."
echo "Please do NOT turn off your device."
dd if=$boot_img of=$uboot_dev conv=fsync >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Something went wrong!!!"
	echo "Please try to run this script again,"
	echo "or contact support for help."
	echo "The most important: PLEASE DO NOT TURN OFF YOUR DEVICE"
	exit 2
fi
dd if=/dev/zero of=$uboot_env conv=fsync >/dev/null 2>&1
dd if=/dev/zero of=$uboot_env_r conv=fsync >/dev/null 2>&1

echo "Updating bootloader successfully."
echo "Device is going to reboot now."
sleep 3
nohup reboot >/dev/null 2>&1 &
