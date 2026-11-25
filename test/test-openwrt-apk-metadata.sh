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
# Verifies OpenWrt .apk metadata produced by package/openwrt/apk-meta.sh
# (the exact code path used by package/openwrt/make.sh):
#
#   1. archive file ownership is root:root (uid/gid 0) for every payload
#      entry, not the build user;
#   2. the apk arch is only emitted for provable targets: an explicit concrete
#      --arch is honored as-is; --arch all derives x86_64 only for the CI
#      filearch x86_64-openwrt-all; every other all/noarch resolves to
#      "unknown" => NO apk (never silently "noarch" while the payload ships
#      target-specific ELF binaries);
#   3. symlinks are archived as symlinks (chown -h, no follow), including
#      links pointing outside the payload;
#   4. failures inside the fakeroot session propagate as rc=1;
#   5. mkpkg success is post-verified with apk adbdump: unless every acl
#      user/group is root, the artifact is deleted and rc=1 (a static apk
#      binary ignores LD_PRELOAD/fakeroot and must not fake the fix);
#   6. missing apk tool => skip rc=2 (ipk unaffected); missing fakeroot with
#      a resolved arch => hard fail rc=1 (an apk is expected, skip would fake
#      success).
#
# Runs the REAL production functions with real fakeroot + apk mkpkg, no mocks.
# Requirements: Linux, regular (non-root) user, apk-tools >= 3.0 with the
# mkpkg and adbdump subcommands (e.g. from the OpenWrt SDK host/bin), and
# fakeroot. apk-tools 3 packages are ADB format, not tar: verification parses
# `apk adbdump` output of the built package.
#
# Uses only mktemp fixtures; never touches /tmp/smartdns-openwrt or any other
# pre-existing /tmp content (that directory belongs to make.sh builds and must
# stay serially owned by them).
#
# Exit codes: 0 = pass, 1 = failure, 77 = skipped (apk or fakeroot missing).
# Usage: sh test/test-openwrt-apk-metadata.sh

set -u

TEST_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$TEST_DIR/.." && pwd)
. "$REPO_ROOT/package/openwrt/apk-meta.sh" || exit 1

PASS=0
FAIL=0

report()
{
	echo "[test-openwrt-apk-metadata] $*"
}

check_eq()
{
	_desc="$1"; _got="$2"; _want="$3"
	if [ "$_got" = "$_want" ]; then
		PASS=$((PASS + 1))
		report "PASS: $_desc"
	else
		FAIL=$((FAIL + 1))
		report "FAIL: $_desc (got '$_got', want '$_want')"
	fi
}

# --- 1. arch resolution (no tools needed) --------------------------------

check_eq "explicit arch honored"              "$(openwrt_apk_resolve_arch x86_64 x86_64)" "x86_64"
check_eq "explicit openwrt sub-arch honored"  "$(openwrt_apk_resolve_arch mips_24kc mips-openwrt-all)" "mips_24kc"
check_eq "CI x86_64 filearch derives x86_64"  "$(openwrt_apk_resolve_arch all x86_64-openwrt-all)" "x86_64"
check_eq "CI mips filearch is unknown"        "$(openwrt_apk_resolve_arch all mips-openwrt-all)" "unknown"
check_eq "CI mipsel filearch is unknown"      "$(openwrt_apk_resolve_arch all mipsel-openwrt-all)" "unknown"
check_eq "CI arm filearch is unknown"         "$(openwrt_apk_resolve_arch all arm-openwrt-all)" "unknown"
check_eq "CI aarch64 filearch is unknown"     "$(openwrt_apk_resolve_arch all aarch64-openwrt-all)" "unknown"
check_eq "CI x86(32) filearch is unknown"     "$(openwrt_apk_resolve_arch all x86-openwrt-all)" "unknown"
check_eq "plain noarch is never derived"      "$(openwrt_apk_resolve_arch noarch x)" "unknown"
check_eq "empty arch is never derived"        "$(openwrt_apk_resolve_arch "" x)" "unknown"
check_eq "noarch + x86_64 filearch is unknown"  "$(openwrt_apk_resolve_arch noarch x86_64-openwrt-all)" "unknown"
check_eq "empty arch + x86_64 filearch is unknown" "$(openwrt_apk_resolve_arch "" x86_64-openwrt-all)" "unknown"

# --- 2. real fakeroot + apk mkpkg metadata --------------------------------

if ! command -v apk >/dev/null 2>&1 || ! command -v fakeroot >/dev/null 2>&1; then
	report "SKIP: apk (mkpkg/adbdump) or fakeroot not on PATH; metadata checks need the OpenWrt SDK host tools."
	[ "$FAIL" -eq 0 ] || exit 1
	exit 77
fi

report "running as uid=$(id -u) ($(id -un)); apk: $(command -v apk); fakeroot: $(command -v fakeroot)"
if [ "$(id -u)" = "0" ]; then
	report "WARNING: running as root weakens the non-root ownership proof (fakeroot still fakes the chown)."
fi

WORK=$(mktemp -d /tmp/smartdns-apk-metadata-test.XXXXXX) || exit 1
trap 'rm -fr "$WORK"' EXIT INT TERM

PAYLOAD="$WORK/root"
mkdir -p "$PAYLOAD/usr/sbin" "$PAYLOAD/etc/smartdns" || exit 1
echo "fake-smartdns-binary" > "$PAYLOAD/usr/sbin/smartdns"
chmod 0755 "$PAYLOAD/usr/sbin/smartdns"
echo "bind :6053" > "$PAYLOAD/etc/smartdns/smartdns.conf"
ln -s smartdns "$PAYLOAD/usr/sbin/smartdns-link"
ln -s ../../etc/smartdns/smartdns.conf "$PAYLOAD/usr/sbin/conf-link"
ln -s /etc/passwd "$PAYLOAD/usr/sbin/probe-link"

POSTINST="$WORK/postinst"
PRERM="$WORK/prerm"
printf '#!/bin/sh\nexit 0\n' > "$POSTINST"
printf '#!/bin/sh\nexit 0\n' > "$PRERM"

OUT="$WORK/smartdns.1.2025.11.15-r0000.x86_64-openwrt-all.apk"
printf 'STALE-OLD-ARTIFACT' > "$WORK/stale-marker"
printf 'STALE-OLD-ARTIFACT' > "$OUT"
openwrt_apk_build "$PAYLOAD" "$OUT" x86_64 1.2025.11.15-r0000 "$POSTINST" "$PRERM"
RC_BUILD=$?
check_eq "openwrt_apk_build succeeds (rc=0)" "$RC_BUILD" "0"
if [ "$RC_BUILD" -ne 0 ]; then
	report "FATAL: cannot continue metadata checks without a built apk"
	exit 1
fi
check_eq "apk output file exists" "$([ -f "$OUT" ] && echo yes || echo no)" "yes"
check_eq "helper verify dump cleaned up" "$([ -f "$OUT.adbdump" ] && echo yes || echo no)" "no"
check_eq "stale old artifact replaced on success" "$(cmp -s "$WORK/stale-marker" "$OUT" && echo kept-stale || echo replaced)" "replaced"

# 2a. dump the built package with `apk adbdump` (ADB format). Write to a
# file and check the exit code first: a failed or truncated dump must never
# silently produce empty (false-PASS) verification results.
DUMP="$WORK/adbdump.txt"
apk adbdump "$OUT" > "$DUMP" 2> "$WORK/adbdump.err"
check_eq "apk adbdump succeeds" "$?" "0"
check_eq "adbdump output is non-empty" "$([ -s "$DUMP" ] && echo yes || echo no)" "yes"
check_eq "adbdump has info section"  "$(grep -c "^info:" "$DUMP")" "1"
check_eq "adbdump has paths section" "$(grep -c "^paths:" "$DUMP")" "1"

# 2b. package arch and name come from the info section
check_eq "adbdump arch is x86_64"   "$(sed -n 's/^  arch: //p' "$DUMP" | head -n 1)" "x86_64"
check_eq "adbdump name is smartdns" "$(sed -n 's/^  name: //p' "$DUMP" | head -n 1)" "smartdns"

# 2c. every acl user/group in the dump must be exactly root; a zero match
# count must not count as a pass, hence the >=12 floor (fixture has ~10 acl
# entries => ~20 user/group lines).
ACL_TOTAL=$(grep -cE '^[[:space:]]*(user|group): ' "$DUMP")
ACL_ROOT=$(grep -cE '^[[:space:]]*(user|group): root$' "$DUMP")
check_eq "acl user/group lines exist (>=12)" "$([ "$ACL_TOTAL" -ge 12 ] && echo yes || echo no)" "yes"
check_eq "all acl user/group are root" "$ACL_ROOT" "$ACL_TOTAL"

# 2d. symlinks archived as symlinks: each records a target; the link pointing
# outside the payload must keep its target (not be inlined as a regular file).
# adbdump prints targets as hex: 2-hex-char type prefix 00a0 + path bytes
# (e.g. "libc.so" -> 00a06c6962632e736f, "/usr/.../run-smartdns" ->
# 00a02f7573722f...6e73), so the expected values below are hex too.
check_eq "exactly 3 symlink targets recorded"   "$(grep -cE '^[[:space:]]*target: 00a0' "$DUMP")" "3"
check_eq "relative symlink target kept"          "$(grep -cE '^[[:space:]]*target: 00a0736d617274646e73$' "$DUMP")" "1"
check_eq "up-tree symlink target kept"           "$(grep -cF 'target: 00a02e2e2f2e2e2f6574632f736d617274646e732f736d617274646e732e636f6e66' "$DUMP")" "1"
check_eq "outside symlink target kept (not inlined)" "$(grep -cF 'target: 00a02f6574632f706173737764' "$DUMP")" "1"
check_eq "smartdns-link entry present"           "$(grep -cE '^[[:space:]]*- name: smartdns-link$' "$DUMP")" "1"
check_eq "probe-link entry present"              "$(grep -cE '^[[:space:]]*- name: probe-link$' "$DUMP")" "1"
check_eq "payload relative symlink still a link" "$([ -L "$PAYLOAD/usr/sbin/smartdns-link" ] && echo yes || echo no)" "yes"
check_eq "conf file archived"                    "$(grep -cE '^[[:space:]]*- name: smartdns.conf$' "$DUMP")" "1"

# --- 3. failure propagation -----------------------------------------------

# 3a. missing payload dir => chown fails inside the fakeroot session => rc=1
openwrt_apk_build "$WORK/no-such-payload" "$WORK/should-not-exist.apk" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
check_eq "missing payload propagates failure (rc=1)" "$?" "1"
check_eq "failed build produced no apk" "$([ -f "$WORK/should-not-exist.apk" ] && echo yes || echo no)" "no"

# 3b. unreadable maintainer script => mkpkg fails inside the session => rc=1
openwrt_apk_build "$PAYLOAD" "$WORK/should-not-exist2.apk" x86_64 1.0-r1 "$WORK/no-such-postinst" "$PRERM" >/dev/null 2>&1
check_eq "missing maintainer script propagates failure (rc=1)" "$?" "1"

# 3c. mkpkg "success" with non-root ownership must be REJECTED by the helper's
# own adbdump post-verification: artifact deleted, rc=1. Uses a narrow apk
# stub (mkpkg touches the output, adbdump prints a runner-owned dump) purely
# to prove the rejection; the positive path above uses the real apk mkpkg.
STUB_BIN="$WORK/stubbin"
mkdir -p "$STUB_BIN" || exit 1
cat > "$STUB_BIN/apk" <<'STUB_EOF'
#!/bin/sh
case "$1" in
mkpkg)
	shift
	out=""
	while [ $# -gt 0 ]; do
		[ "$1" = "--output" ] && out="$2"
		shift
	done
	: > "$out"
	exit 0
	;;
adbdump)
	echo "info:"
	echo "  arch: x86_64"
	echo "paths:"
	echo "  - acl:"
	echo "      user: runner"
	echo "      group: runner"
	exit 0
	;;
*)
	exit 1
	;;
esac
STUB_EOF
chmod +x "$STUB_BIN/apk" || exit 1
SAVE_PATH="$PATH"
PATH="$STUB_BIN:$PATH"
OUT_STUB="$WORK/stub-runner.apk"
openwrt_apk_build "$PAYLOAD" "$OUT_STUB" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
RC_STUB=$?
PATH="$SAVE_PATH"
check_eq "non-root ownership rejected despite mkpkg success (rc=1)" "$RC_STUB" "1"
check_eq "rejected artifact deleted"  "$([ -f "$OUT_STUB" ] && echo yes || echo no)" "no"
check_eq "verify dump cleaned up"     "$([ -f "$OUT_STUB.adbdump" ] && echo yes || echo no)" "no"

# 3d. a previously valid artifact at the output path must byte-survive every
# failure path (mkpkg failure and verification rejection): only this run's
# private candidate is cleaned up, never the old output.
OLD_OUT="$WORK/keep-old.apk"
OLD_MARK="$WORK/old-marker"
printf 'OLD-VALID-BYTES' > "$OLD_MARK"
cp "$OLD_MARK" "$OLD_OUT"
openwrt_apk_build "$PAYLOAD" "$OLD_OUT" x86_64 1.0-r1 "$WORK/no-such-postinst" "$PRERM" >/dev/null 2>&1
check_eq "mkpkg failure keeps old artifact (rc=1)" "$?" "1"
check_eq "old artifact bytes intact after mkpkg failure" "$(cmp -s "$OLD_MARK" "$OLD_OUT" && echo yes || echo no)" "yes"
check_eq "no workdir left after mkpkg failure" "$(ls -d "$WORK"/.smartdns-apk-pkg.* 2>/dev/null | wc -l)" "0"
SAVE_PATH="$PATH"
PATH="$STUB_BIN:$PATH"
openwrt_apk_build "$PAYLOAD" "$OLD_OUT" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
RC_OLD_STUB=$?
PATH="$SAVE_PATH"
check_eq "verification rejection keeps old artifact (rc=1)" "$RC_OLD_STUB" "1"
check_eq "old artifact bytes intact after rejection" "$(cmp -s "$OLD_MARK" "$OLD_OUT" && echo yes || echo no)" "yes"
check_eq "no workdir left after rejection" "$(ls -d "$WORK"/.smartdns-apk-pkg.* 2>/dev/null | wc -l)" "0"

# 3e. destination traps: an existing directory (or a symlink to one) at the
# output path must never swallow the package; the directory and its contents
# stay unchanged. mv -fT makes the destination a file.
DIR_OUT="$WORK/dir-out"
mkdir -p "$DIR_OUT" || exit 1
printf 'DIR-CONTENT' > "$WORK/dir-content-marker"
cp "$WORK/dir-content-marker" "$DIR_OUT/keepme"
openwrt_apk_build "$PAYLOAD" "$DIR_OUT" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
check_eq "directory destination fails (rc=1)" "$?" "1"
check_eq "directory still a directory" "$([ -d "$DIR_OUT" ] && echo yes || echo no)" "yes"
check_eq "directory content unchanged" "$(cmp -s "$WORK/dir-content-marker" "$DIR_OUT/keepme" && echo yes || echo no)" "yes"
check_eq "no apk moved into directory" "$(ls "$DIR_OUT" | wc -l)" "1"
check_eq "no workdir left after directory failure" "$(ls -d "$WORK"/.smartdns-apk-pkg.* 2>/dev/null | wc -l)" "0"

SYM_DIR="$WORK/sym-target"
mkdir -p "$SYM_DIR" || exit 1
cp "$WORK/dir-content-marker" "$SYM_DIR/keepme"
ln -s "$SYM_DIR" "$WORK/sym-out"
openwrt_apk_build "$PAYLOAD" "$WORK/sym-out" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
RC_SYM=$?
check_eq "symlink-to-directory destination succeeds via mv -fT" "$RC_SYM" "0"
check_eq "symlink replaced by regular apk file" "$([ -f "$WORK/sym-out" ] && [ ! -L "$WORK/sym-out" ] && echo yes || echo no)" "yes"
check_eq "symlinked directory content unchanged" "$(cmp -s "$WORK/dir-content-marker" "$SYM_DIR/keepme" && echo yes || echo no)" "yes"
check_eq "no apk moved into symlinked directory" "$(ls "$SYM_DIR" | wc -l)" "1"
check_eq "no workdir left after symlink success" "$(ls -d "$WORK"/.smartdns-apk-pkg.* 2>/dev/null | wc -l)" "0"

# --- 4. tool availability semantics ----------------------------------------

# apk tool itself missing => skip (rc=2); the ipk is unaffected.
SAVE_PATH="$PATH"
# Deliberately hide tools for the missing-command test.
# shellcheck disable=SC2123
PATH="/nonexistent-openwrt-apk-test"
openwrt_apk_build "$PAYLOAD" "$WORK/should-not-exist3.apk" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
RC_NOAPK=$?
PATH="$SAVE_PATH"
check_eq "missing apk => skip (rc=2)" "$RC_NOAPK" "2"

# apk present but fakeroot missing => must hard fail (rc=1): the arch is
# resolved, an apk package is expected, and skipping would fake success.
FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN" || exit 1
ln -s "$(command -v apk)" "$FAKE_BIN/apk" || exit 1
SAVE_PATH="$PATH"
PATH="$FAKE_BIN"
openwrt_apk_build "$PAYLOAD" "$WORK/should-not-exist4.apk" x86_64 1.0-r1 "$POSTINST" "$PRERM" >/dev/null 2>&1
RC_NOFAKEROOT=$?
PATH="$SAVE_PATH"
check_eq "missing fakeroot with arch resolved => fail (rc=1)" "$RC_NOFAKEROOT" "1"
check_eq "failed build produced no apk (2)" "$([ -f "$WORK/should-not-exist4.apk" ] && echo yes || echo no)" "no"

# --- summary ---------------------------------------------------------------

report "summary: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
exit 0
