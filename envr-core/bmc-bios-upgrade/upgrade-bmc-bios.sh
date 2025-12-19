#!/bin/bash

tmp_firmware_path="/tmp/firmware.tar"
bmc_version="2.05.13"
bmc_md5sum="a309ce905c83130ae546a538f73afda1"
bios_version="2.02.0022"
bios_md5sum="97e24a8f44c518aeec62037a9be1c6b2"
timeout=300

enable_bmc_interface() {
	ifconfig usb0 169.254.0.18
	echo "Checking BMC connectivity..."
	ping -q -c 2 169.254.0.17 -W 2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "failed"
		exit 1
	fi
	echo "BMC is connected."
}

disable_bmc_interface() {
	ifconfig usb0 down
	echo "BMC is disconnected."
}

upgrade_image() {
	echo "Downloading $1..."
	curl -sL -o ${tmp_firmware_path} "https://github.com/ubiquiti/support-tools/blob/envrcore-upgrade-bmc-bios/envr-core/bmc-bios-upgrade/$1?raw=true"
	if [ $? -ne 0 ]; then
		echo "Failed."
		exit 1
	fi
	echo "Done."

	echo "Checking md5sum..."
	md5sum -b ${tmp_firmware_path} | grep -qw $2
	if [ $? -ne 0 ]; then
		echo "Failed."
		exit 1
	fi
	echo "Done."

	echo "Upgrading $1..."
	curl -k -u root:ui -H "Content-Type: multipart/form-data" -X POST -F 'UpdateParameters={"Targets":["'/redfish/v1/Managers/bmc'"],"@Redfish.OperationApplyTime":"Immediate"};type=application/json' -F "UpdateFile=@${tmp_firmware_path};type=application/octet-stream" https://169.254.0.17/redfish/v1/UpdateService/update
	if [ $? -ne 0 ]; then
		echo "failed to request upgrade."
		exit 1
	fi
}

check_bmc_version() {
	local output
	echo "Checking BMC version..."
	output=$(curl -k -u root:ui https://169.254.0.17/redfish/v1/Managers/bmc 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "Failed to get BMC info"
		return 0
	fi
	if [ $(echo $output | jq -r .FirmwareVersion) == "${bmc_version}" ]; then
		return 0
	fi
	return 1
}

check_bios_version() {
	local output
	echo "Checking BIOS version..."
	output=$(curl -k -u root:ui https://169.254.0.17/redfish/v1/UpdateService/FirmwareInventory/bios_active 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "Failed to get BIOS info"
		exit 1
	fi
	if [ $(echo $output | jq -r .Version) == "${bios_version}" ]; then
		return 0
	fi
	return 1
}

retry_check() {
	local start_time=$(cut -d\  -f1 /proc/uptime)
	echo "Checking upgrade progress..."
	while $1; do
		sleep 5
		time_runs=time_runs=$(awk "BEGIN { print $(cut -d\  -f1 /proc/uptime) - ${start_time} }")
		if [ $(awk "BEGIN { print (${time_runs} >= ${timeout}) }") -eq 1 ]; then
			echo "Timeout"
			break
		fi
	done
	echo "Done."
}

enable_bmc_interface
if check_bmc_version; then
	upgrade_image bmc.tar ${bmc_md5sum}
	retry_check check_bmc_version
else
	echo "No need to upgrade BMC."
fi

if check_bios_version; then
	upgrade_image bios.tar ${bios_md5sum}
	retry_check check_bios_version
else
	echo "No need to upgrade BIOS."
fi
