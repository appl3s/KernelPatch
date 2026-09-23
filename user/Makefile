# Build the kpmctl KPM loader/control tool for arm64 Android.
#
# With the NDK (recommended, produces a static binary):
#   make CC=$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android24-clang
# With a bare aarch64 clang:
#   make CC="clang --target=aarch64-linux-android24"
#
# Output: kpmctl  ->  adb push to /data/local/tmp, run as root/adb shell.

CC ?= clang
CFLAGS ?= -static -O2 -Wall -Wextra -Wno-unused-parameter

kpmctl: kpmctl.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f kpmctl

.PHONY: clean
