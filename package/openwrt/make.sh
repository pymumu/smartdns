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
SMARTDNS_BIN=$SMARTDNS_DIR/src/smartdns
SMARTDNS_CONF=$SMARTDNS_DIR/etc/smartdns/smartdns.conf
ADDRESS_CONF=$CURR_DIR/address.conf
BLACKLIST_IP_CONF=$CURR_DIR/blacklist-ip.conf
CUSTOM_CONF=$CURR_DIR/custom.conf

showhelp()
{
	echo "Usage: make [OPTION]"
	echo "Options:"
	echo " -o               output directory."
	echo " --arch           archtecture."
	echo " --ver            version."
	echo " -h               show this message."
}

build()
{
	ROOT=/tmp/smartdns-openwrt
	rm -fr $ROOT

	mkdir -p $ROOT
	cp $CURR_DIR/* $ROOT/ -af
	cd $ROOT/
	mkdir $ROOT/root/usr/sbin -p
	mkdir $ROOT/root/etc/init.d -p
	mkdir $ROOT/root/etc/smartdns/ -p

	cp $SMARTDNS_CONF  $ROOT/root/etc/smartdns/
	cp $ADDRESS_CONF $ROOT/root/etc/smartdns/
	cp $BLACKLIST_IP_CONF $ROOT/root/etc/smartdns/
	cp $CUSTOM_CONF $ROOT/root/etc/smartdns/
	cp $CURR_DIR/files/etc $ROOT/root/ -af
	cp $SMARTDNS_BIN $ROOT/root/usr/sbin
	if [ $? -ne 0 ]; then
		echo "copy smartdns file failed."
		rm -fr $ROOT/
		return 1
	fi

	chmod +x $ROOT/root/etc/init.d/smartdns
	INST_SIZE="`du -sb $ROOT/root/ | awk '{print $1}'`"

	sed -i "s/^Architecture.*/Architecture: $ARCH/g" $ROOT/control/control
	sed -i "s/Version:.*/Version: $VER/" $ROOT/control/control
	sed -i "s/^\(bind .*\):53/\1:6053/g" $ROOT/root/etc/smartdns/smartdns.conf
	if [ ! -z "$INST_SIZE" ]; then
		echo "Installed-Size: $INST_SIZE" >> $ROOT/control/control
	fi

	cd $ROOT/control
	chmod +x *
	tar zcf ../control.tar.gz --owner=0 --group=0 ./
	cd $ROOT

	tar zcf $ROOT/data.tar.gz -C root --owner=0 --group=0 .
	tar zcf $OUTPUTDIR/smartdns.$VER.$FILEARCH.ipk --owner=0 --group=0 control.tar.gz data.tar.gz debian-binary
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


