#!/bin/sh
#
# Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
#
# smartdns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# smartdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Helpers for OpenWrt .apk package metadata.
# POSIX sh library: sourced by package/openwrt/make.sh and
# test/test-openwrt-apk-metadata.sh. Do not execute directly.

# openwrt_apk_resolve_arch <ARCH> <FILEARCH>
# Print the .apk arch, or "unknown" when no concrete OpenWrt package arch is
# provable. An explicit --arch (anything except all/noarch) is honored as-is.
# With --arch all, only the CI filearch x86_64-openwrt-all maps, to x86_64,
# which is the exact OpenWrt package arch for the 64-bit x86 target. noarch
# and an empty arch are unconditionally unknown, as is every other all build:
# OpenWrt arch names are per-target
# (mips_24kc, arm_cortex-a7_neon-vfpv4, i386_pentium4, ...) and are not
# inferred here, and a payload with target-specific ELF binaries is never
# published as noarch.
openwrt_apk_resolve_arch()
{
	_arch="$1"
	_filearch="$2"

	case "$_arch" in
	all)
		if [ "$_filearch" = "x86_64-openwrt-all" ]; then
			echo "x86_64"
		else
			echo "unknown"
		fi
		;;
	noarch|"")
		echo "unknown"
		;;
	*)
		echo "$_arch"
		;;
	esac
	return 0
}

# openwrt_apk_arch_notice <ARCH> <FILEARCH>
# Explain why no .apk is produced for this target.
openwrt_apk_arch_notice()
{
	echo "== warning: skip apk package for arch='$1' filearch='$2': no provable OpenWrt package arch. =="
	echo "   OpenWrt arch names are per-target and are not guessed, and an ELF payload is not published as noarch."
	echo "   Rebuild with an explicit OpenWrt arch (e.g. --arch x86_64, or a per-target name) to get an apk package."
	echo "   The ipk package is still built."
	return 0
}

# openwrt_apk_build <payload-dir> <output.apk> <arch> <version> <postinst> <prerm>
# The .apk must record root:root (uid/gid 0) ownership for every payload
# entry; apk-tools 3 mkpkg has no owner option and would archive the real
# build user instead. Therefore chown -hR 0:0 and apk mkpkg run inside ONE
# fakeroot session: chown -h changes symlinks themselves (never following
# them) and no workspace file is really chowned. A static apk binary ignores
# LD_PRELOAD (hence fakeroot), so after mkpkg succeeds the built package is
# re-dumped with apk adbdump and rejected unless every acl user/group is root.
# Packaging and verification run on a private mktemp candidate in the output
# directory; the final output is replaced by mv only after full success, so a
# failed run never destroys a previously valid artifact.
#
# Return codes: 0 = apk built and verified; 1 = failure (propagates, build
# fails; also used for verification rejection); 2 = apk tool not available
# (skip, ipk unaffected).
openwrt_apk_build()
{
	_payload="$1"
	_output="$2"
	_arch="$3"
	_version="$4"
	_postinst="$5"
	_prerm="$6"

	if ! command -v apk >/dev/null 2>&1; then
		echo "== warning: apk tool not found, skip build apk package. PATH=$PATH =="
		return 2
	fi
	if ! command -v fakeroot >/dev/null 2>&1; then
		echo "build apk package failed: fakeroot not found, cannot record root:root ownership."
		return 1
	fi

	# Build and verify a private candidate next to the output (same file
	# system); only a fully verified candidate replaces the final output via
	# mv, so the previous artifact at _output survives every failure path.
	# Subshell + internal trap: the caller's trap is never touched.
	_output_dir=$(dirname "$_output")
	_candidate=$(mktemp "$_output_dir/.smartdns-apk-candidate.XXXXXX") || return 1
	rm -f "$_candidate"
	(
		trap 'rm -f "$_candidate" "$_candidate.adbdump"' EXIT INT TERM

		fakeroot -- sh -c '
			set -e
			payload="$1"; output="$2"; arch="$3"; version="$4"; postinst="$5"; prerm="$6"
			chown -hR 0:0 "$payload"
			apk mkpkg \
				--info "name:smartdns" \
				--info "version:$version" \
				--info "description:A smartdns Server" \
				--info "arch:$arch" \
				--info "license:GPL" \
				--info "origin: https://github.com/pymumu/smartdns.git" \
				--info "depends:libc libpthread" \
				--script "post-install:$postinst" \
				--script "pre-deinstall:$prerm" \
				--files "$payload/" \
				--output "$output"
		' sh "$_payload" "$_candidate" "$_arch" "$_version" "$_postinst" "$_prerm"
		if [ $? -ne 0 ]; then
			echo "build apk package failed."
			exit 1
		fi

		# Post-verify the candidate: dump it and confirm root:root ownership for
		# every acl (at least one user/group pair). Redirect to a file so a
		# failed dump can never pass silently through a pipeline.
		_verify_dump="$_candidate.adbdump"
		if ! apk adbdump "$_candidate" > "$_verify_dump" 2>/dev/null; then
			echo "build apk package failed: adbdump verification of the artifact failed."
			exit 1
		fi
		_acl_total=$(grep -cE '^[[:space:]]*(user|group): ' "$_verify_dump")
		_acl_root=$(grep -cE '^[[:space:]]*(user|group): root$' "$_verify_dump")
		if [ "$_acl_total" -lt 2 ] || [ "$_acl_total" -ne "$_acl_root" ]; then
			echo "build apk package failed: artifact ownership is not root:root (acl root: $_acl_root/$_acl_total)."
			exit 1
		fi

		mv -f "$_candidate" "$_output" || exit 1
	)
	if [ $? -ne 0 ]; then
		return 1
	fi
	return 0
}
