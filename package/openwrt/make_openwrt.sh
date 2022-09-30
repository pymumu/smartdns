#!/bin/sh -e
#
# Copyright (C) 2021 Xingwang Liao
#

VER="`date +"1.%Y.%m.%d-%H%M"`"

dir="$(cd "$(dirname "$0")" ; pwd)"
#dir=/home/runner/work/smartdns/smartdns/package/openwrt
custom_dir="$(eval echo "~/custom")"

package_name="smartdns"
golang_commit="$OPENWRT_GOLANG_COMMIT"

cache_dir=${CACHE_DIR:-"~/cache"}

sdk_url_path=${SDK_URL_PATH:-"https://downloads.openwrt.org/snapshots/targets/x86/64"}
sdk_name=${SDK_NAME:-"-sdk-x86-64_"}

sdk_home=${SDK_HOME:-"~/sdk"}

sdk_home_dir="$(eval echo "$sdk_home")"

test -d "$sdk_home_dir" || mkdir -p "$sdk_home_dir"

sdk_dir="$(eval echo "$cache_dir/sdk")"
dl_dir="$(eval echo "$cache_dir/dl")"
feeds_dir="$(eval echo "$cache_dir/feeds")"

test -d "$sdk_dir" || mkdir -p "$sdk_dir"
test -d "$dl_dir" || mkdir -p "$dl_dir"
test -d "$feeds_dir" || mkdir -p "$feeds_dir"

cd "$sdk_dir"

if ! ( wget -q -O - "$sdk_url_path/sha256sums" | \
	grep -- "$sdk_name" > sha256sums.small 2>/dev/null ) ; then
	echo "Can not find ${sdk_name} file in sha256sums."
	exit 1
fi

sdk_file="$(cut -d' ' -f2 < sha256sums.small | sed 's/*//g')"

if ! sha256sum -c ./sha256sums.small >/dev/null 2>&1 ; then
	wget -q -O "$sdk_file" "$sdk_url_path/$sdk_file"

	if ! sha256sum -c ./sha256sums.small >/dev/null 2>&1 ; then
		echo "SDK can not be verified!"
		exit 1
	fi
fi

cd "$dir"

file "$sdk_dir/$sdk_file"
tar -Jxf "$sdk_dir/$sdk_file" -C "$sdk_home_dir" --strip=1

cd "$sdk_home_dir"

( test -d "dl" && rm -rf "dl" ) || true
( test -d "feeds" && rm -rf "feeds" ) || true

ln -sf "$dl_dir" "dl"
ln -sf "$feeds_dir" "feeds"

cp -f feeds.conf.default feeds.conf

sed -i '
s#git.openwrt.org/openwrt/openwrt#github.com/openwrt/openwrt#
s#git.openwrt.org/feed/packages#github.com/openwrt/packages#
s#git.openwrt.org/project/luci#github.com/openwrt/luci#
s#git.openwrt.org/feed/telephony#github.com/openwrt/telephony#
' feeds.conf

echo "src-link custom $custom_dir" >> feeds.conf

./scripts/feeds update -a

( test -d "feeds/packages/net/$package_name" && \
	rm -rf "feeds/packages/net/$package_name" ) || true

# replace golang with version defined in env
if [ -n "$golang_commit" ] ; then
	( test -d "feeds/packages/lang/golang" && \
		rm -rf "feeds/packages/lang/golang" ) || true

	curl "https://codeload.github.com/openwrt/packages/tar.gz/$golang_commit" | \
		tar -xz -C "feeds/packages/lang" --strip=2 "packages-$golang_commit/lang/golang"
fi

mkdir -p "$custom_dir"
cp -rH "$dir" "$custom_dir/$package_name"
mkdir -p "$custom_dir/$package_name/src"
cp -rH "$dir/../../src" "$custom_dir/$package_name/src/src"
mkdir -p "$custom_dir/$package_name/src/package"
cp -rH "$dir" "$custom_dir/$package_name/src/package/openwrt"

sed -i "s/PKG_VERSION:=.*/PKG_VERSION:=$VER/" $custom_dir/$package_name/Makefile

sed -i "/PKG_SOURCE:=.*/d" $custom_dir/$package_name/Makefile
sed -i "/PKG_SOURCE_SUBDIR:=.*/d" $custom_dir/$package_name/Makefile
sed -i "/PKG_SOURCE_PROTO:=.*/d" $custom_dir/$package_name/Makefile
sed -i "/PKG_SOURCE_URL:=.*/d" $custom_dir/$package_name/Makefile
sed -i "/PKG_SOURCE_VERSION:=.*/d" $custom_dir/$package_name/Makefile
sed -i "/PKG_MIRROR_HASH:=.*/d" $custom_dir/$package_name/Makefile

echo "----checkpoint filetree------"
tree "$custom_dir/$package_name" -L 5
echo "-----------------------------"

./scripts/feeds install -a
./scripts/feeds update custom
./scripts/feeds install -f -p custom smartdns

make defconfig

make package/${package_name}/clean
make package/${package_name}/compile V=s

cd "$dir"
find "$sdk_home_dir/bin/" -type f -name "${package_name}*.ipk" -exec cp -f {} "$dir" \;
