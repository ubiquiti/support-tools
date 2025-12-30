#!/bin/bash

tmp_firmware_path="/tmp/firmware.tar"
bmc_version="2.05.13"
bmc_md5sum="a309ce905c83130ae546a538f73afda1"
bios_version="2.02.UI09"
bios_md5sum="d56abfb7642f5f09853ea2ad12728614"
timeout=300
bios_task_id=""

check_sysid() {
	local sysid=$(awk -F= 'match($1, /systemid/) {print $2}' /proc/ubnthal/system.info)
	if [ "da28" != "$sysid" ]; then
		echo "Unsupported model $sysid"
		exit 1
	fi
}

check_bmc_connectivity() {
	printf "Checking BMC connectivity..."
	ping -q -c 2 169.254.0.17 -W 2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "failed"
		return 0
	fi
	echo "Connected."
    return 1
}

enable_bmc_interface() {
	ifconfig usb0 169.254.0.18
    check_bmc_connectivity
}

disable_bmc_interface() {
	ifconfig usb0 down
	echo "BMC is disconnected."
}

upgrade_image() {
	printf "Downloading $1..."
	curl -sL -o ${tmp_firmware_path} "https://github.com/ubiquiti/support-tools/blob/master/envr-core/bmc-bios-upgrade/$1?raw=true" 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "Failed."
		exit 1
	fi
	echo "Done."

	printf "Checking md5sum..."
	md5sum -b ${tmp_firmware_path} | grep -qw $2
	if [ $? -ne 0 ]; then
		echo "Failed."
		exit 1
	fi
	echo "Done."

	printf "Uploading $1..."
	output=$(curl -k -u root:ui -H "Content-Type: multipart/form-data" -X POST -F 'UpdateParameters={"Targets":["'/redfish/v1/Managers/bmc'"],"@Redfish.OperationApplyTime":"Immediate"};type=application/json' -F "UpdateFile=@${tmp_firmware_path};type=application/octet-stream" https://169.254.0.17/redfish/v1/UpdateService/update 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "Failed to request upgrade."
		exit 1
	fi
    if [ "$1" == "bios.tar" ]; then
        bios_task_id=$(echo $output | jq -r '."@odata.id"')
        echo ${bios_task_id}
    else
        echo "Done."
    fi
}

check_bmc_version() {
	local output version
	printf "Checking BMC version..."
	output=$(curl -k -u root:ui https://169.254.0.17/redfish/v1/Managers/bmc 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "Failed to get BMC info."
		return 1
	fi
    version=$(echo $output | jq -r .FirmwareVersion)
    echo ${version}
	if [ "${version}" == "${bmc_version}" ]; then
		return 1
	fi
	return 0
}

check_bios_version() {
	local output version
	printf "Checking BIOS version..."
	output=$(curl -k -u root:ui https://169.254.0.17/redfish/v1/UpdateService/FirmwareInventory/bios_active 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "Failed to get BIOS info"
		return 1
	fi
    version=$(echo $output | jq -r .Version)
    echo ${version}
	if [ "${version}" == "${bios_version}" ]; then
		return 1
	fi
	return 0
}

check_bios_upgrade_status() {
    local output status
    printf "Checking bios upgrade status..."
    while [ ! -z "${bios_task_id}" ]; do
        output=$(curl -k -u root:ui https://169.254.0.17${bios_task_id} 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "Failed to get task status"
            return
        fi
        status=$(echo $output | jq -r .TaskState)
        if [ "${status}" == "Completed" ]; then
            echo "Completed."
            return
        else
            printf "%s." ${status}
        fi
        sleep 5
    done
    echo "No bios upgrade task."
}

retry_check() {
	local start_time=$(cut -d\  -f1 /proc/uptime)
	printf "Checking upgrade progress..."
	while $1; do
		sleep 5
		time_runs=$(awk "BEGIN { print $(cut -d\  -f1 /proc/uptime) - ${start_time} }")
		if [ $(awk "BEGIN { print (${time_runs} >= ${timeout}) }") -eq 1 ]; then
			echo "Timeout"
			break
		fi
	done
	echo "Done."
}


check_sysid
enable_bmc_interface
if check_bios_version; then
	upgrade_image bios.tar ${bios_md5sum}
    check_bios_upgrade_status
	retry_check check_bios_version
	sleep 10
else
	echo "No need to upgrade BIOS."
fi
if check_bmc_version; then
	upgrade_image bmc.tar ${bmc_md5sum}
	retry_check check_bmc_connectivity
	retry_check check_bmc_version
else
	echo "No need to upgrade BMC."
fi
disable_bmc_interface
echo "Check and upgrade BIOS/BMC done."
