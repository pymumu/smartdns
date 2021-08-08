#!/bin/sh
#
# Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
CURR_DIR=$(cd $(dirname $0);pwd)

VER="`date +"1.%Y.%m.%d-%H%M"`"
SMARTDNS_DIR=$CURR_DIR/../../
PO2LMO=

showhelp()
{
	echo "Usage: make [OPTION]"
	echo "Options:"
	echo " -o               output directory."
	echo " --arch           archtecture."
	echo " --ver            version."
	echo " -h               show this message."
}

build_tool()
{
	make -C $ROOT/tool/po2lmo -j 
	PO2LMO="$ROOT/tool/po2lmo/src/po2lmo"

}

clean_tool()
{
	make -C $ROOT/tool/po2lmo clean
}

build()
{

	ROOT=/tmp/luci-app-smartdns
	rm -fr $ROOT

	mkdir -p $ROOT
	cp $CURR_DIR/* $ROOT/ -af
	cd $ROOT/
	build_tool
	
	mkdir $ROOT/root/usr/lib/lua/luci -p
	mkdir $ROOT/root/usr/share/rpcd/acl.d/ -p
	cp $ROOT/files/luci/i18n $ROOT/root/usr/lib/lua/luci/ -avf

	#Generate Language
	$PO2LMO $ROOT/files/luci/i18n/smartdns.zh-cn.po $ROOT/root/usr/lib/lua/luci/i18n/smartdns.zh-cn.lmo
	rm $ROOT/root/usr/lib/lua/luci/i18n/smartdns.zh-cn.po

	cp $ROOT/files/root/* $ROOT/root/ -avf
	INST_SIZE="`du -sb $ROOT/root/ | awk '{print $1}'`"
	
	sed -i "s/^Architecture.*/Architecture: all/g" $ROOT/control/control
	sed -i "s/Version:.*/Version: $VER/" $ROOT/control/control

	if [ ! -z "$INST_SIZE" ]; then
		echo "Installed-Size: $INST_SIZE" >> $ROOT/control/control
	fi

	cd $ROOT/control
	chmod +x *
	tar zcf ../control.tar.gz ./
	cd $ROOT

	tar zcf $ROOT/data.tar.gz -C root .
	tar zcf $OUTPUTDIR/luci-app-smartdns.$VER.$FILEARCH.ipk ./control.tar.gz ./data.tar.gz ./debian-binary

	rm -fr $ROOT/
}

main()
{
	OPTS=`getopt -o o:h --long arch:,ver:,filearch: \
		-n  "" -- "$@"`

	if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

	# Note the quotes around `$TEMP': they are essential!
	eval set -- "$OPTS"

	while true; do
		case "$1" in
		--arch)
			ARCH="$2"
			shift 2;;
		--filearch)
			FILEARCH="$2"
			shift 2;;
		--ver)
			VER="$2"
			shift 2;;
		-o )
			OUTPUTDIR="$2"
			shift 2;;
		-h | --help )
			showhelp
			return 0
			shift ;;
		-- ) shift; break ;;
		* ) break ;;
		esac
	done

	if [ -z "$ARCH" ]; then
		echo "please input arch."
		return 1;
	fi

	if [ -z "$FILEARCH" ]; then
		FILEARCH=$ARCH
	fi

	if [ -z "$OUTPUTDIR" ]; then
		OUTPUTDIR=$CURR_DIR;
	fi

	build
}

main $@
exit $?


