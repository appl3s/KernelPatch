#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# klnpatch.sh — bake kallsyms_lookup_name into kernelpatch.ko so it loads with
# a bare `insmod kernelpatch.ko` (no `kln=` module_param).
#
# The LKM ships a binary-patchable slot in its .data:
#   struct kp_kln_slot { unsigned long magic; unsigned long addr; };
# where magic = 0x544f4c534e4c504b (little-endian file bytes "KPLNSLOT") and
# addr = 0. This script finds the magic by byte-scan and overwrites addr with
# the real kallsyms_lookup_name address, then writes the .ko back in place.
#
# Uses only toybox (awk / grep -ab / dd / printf / shell arithmetic), no compiler.
#
# Usage (on-device, as root):
#   sh klnpatch.sh <kernelpatch.ko>                # read addr from /proc/kallsyms
#   sh klnpatch.sh <kernelpatch.ko> 0x<addr>       # use a given address
#
# Then:
#   insmod <kernelpatch.ko>
#
# Why this works:
#  - The magic is ASCII "KPLNSLOT", so `grep -abo` can locate it as a string.
#  - `dd ... conv=notrunc` writes 8 bytes without truncating the multi-MB .ko.
#  - The 64-bit address is split byte-by-byte with $(( (a >> (i*8)) & 0xff )) and
#    each byte formatted with printf '%02x'; toybox `printf '%x'` can mangle
#    full 64-bit kernel addresses, but shell $(( )) is 64-bit on Android.

set -eu

usage() {
	echo "usage: sh klnpatch.sh <kernelpatch.ko> [0x<addr>]" >&2
	echo "  no addr  -> read kallsyms_lookup_name from /proc/kallsyms" >&2
	echo "  0x<addr> -> use given address" >&2
	exit 1
}

[ $# -eq 1 ] || [ $# -eq 2 ] || usage

KO="$1"

if [ $# -eq 2 ]; then
	KLN="$2"
	case "$KLN" in
		0x*|0X*) KLN="0x${KLN#*[xX]}" ;;
		*) KLN="0x$KLN" ;;
	esac
else
	KLN=$(awk '$3=="kallsyms_lookup_name"{print "0x"$1; exit}' /proc/kallsyms)
	if [ -z "$KLN" ]; then
		echo "klnpatch: kallsyms_lookup_name not found in /proc/kallsyms" >&2
		echo "  (kptr_restrict? pass the address explicitly: sh klnpatch.sh <ko> 0x<addr>)" >&2
		exit 1
	fi
fi

# Validate it parses as a number (strip 0x, ensure hex digits left).
_h=${KLN#0x}
case "$_h" in
	''|*[!0-9a-fA-F]*) echo "klnpatch: invalid address: $KLN" >&2; exit 1 ;;
esac

# Locate the "KPLNSLOT" magic; addr slot is the 8 bytes right after it.
_line=$(grep -abo KPLNSLOT "$KO" | head -n 1) || true
_off=${_line%%:*}
if [ -z "${_off:-}" ]; then
	echo "klnpatch: KPLNSLOT magic not found in $KO" >&2
	echo "  (not a kernelpatch.ko, or built without the patchable slot)" >&2
	exit 1
fi
OFF=$((_off + 8))

# Build the 8 little-endian bytes of the address.
ESC=""
i=0
while [ $i -lt 8 ]; do
	b=$(( (${KLN} >> (i * 8)) & 0xff ))
	ESC="$ESC\\x$(printf '%02x' "$b")"
	i=$((i + 1))
done

printf '%b' "$ESC" | dd of="$KO" bs=1 seek="$OFF" count=8 conv=notrunc 2>/dev/null

echo "klnpatch: patched $KO: kln=$KLN at file offset 0x$(printf '%x' "$OFF")"
echo "klnpatch: now run: insmod $KO"
