#!/bin/bash

TMP_DIR="/tmp"

TOOL="218xfwdl"
TOOL_MD5=14816025073323388b917b78acb6909a

FW_BIN="240821_20_AA_02.bin"
FW_MD5=17ae845d2d0adc7b39e4a8d04133dbb1

TARGET_VER="24 08 21 20 aa 02"

GITHUB_BASE="https://github.com/ubiquiti/support-tools/raw/master/unas-pro/firmware/asm2812"

sysid=$(awk -F= '/systemid/ { print $2 }' /proc/ubnthal/system.info)

case "$sysid" in
ea63 | ea67)
	;;
*)
	echo "Invalid product: $sysid"
	exit 1
	;;
esac

download_files() {
	echo "==> Downloading files..."
	curl -sL -o "$TMP_DIR/$TOOL" "$GITHUB_BASE/$TOOL"
	curl -sL -o "$TMP_DIR/$FW_BIN" "$GITHUB_BASE/$FW_BIN"
	chmod 755 "$TMP_DIR/$TOOL"
}

check_files() {
	pushd "$TMP_DIR" >/dev/null
	md5sum -c <<EOF
${TOOL_MD5}  ${TOOL}
${FW_MD5}  ${FW_BIN}
EOF
	status=$?
	popd >/dev/null

	if [ $status -ne 0 ]; then
		echo " - File checksum mismatch"
		return 1
	fi

	if [[ ! -x "${TMP_DIR}/${TOOL}" ]]; then
		echo " - ${TOOL} not executable"
		return 1
	fi

	return 0
}

check_version() {
	"${TMP_DIR}/${TOOL}" /S 2>/dev/null | grep -q "${TARGET_VER}"
}

if ! download_files; then
	exit 1
fi

if ! check_files; then
	exit 1
fi

if check_version; then
	echo "==> ASM2812 firmware is already up to date (${TARGET_VER})"
	exit 0
fi

echo "==> Updating ASM2812 firmware..."
echo "    PLEASE DO NOT TURN OFF THE DEVICE."

if ! "${TMP_DIR}/${TOOL}" /U "${TMP_DIR}/${FW_BIN}"; then
	echo "Firmware update FAILED. System will not reboot."
	echo "Please contact support for help."
	exit 2
fi

echo "==> Verifying firmware version..."

if ! check_version; then
	echo "Firmware verification FAILED. Version mismatch after update."
	echo "System will not reboot. Please contact support for help."
	exit 3
fi

echo "==> Firmware update completed and verified successfully"
echo "==> Rebooting system..."

sleep 1
reboot
