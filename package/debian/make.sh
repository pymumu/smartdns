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
	ROOT=/tmp/smartdns-deiban
	rm -fr $ROOT
	mkdir -p $ROOT
	cd $ROOT/

	cp $CURR_DIR/DEBIAN $ROOT/ -af
	CONTROL=$ROOT/DEBIAN/control
	mkdir $ROOT/usr/sbin -p
	mkdir $ROOT/etc/smartdns/ -p
	mkdir $ROOT/etc/default/ -p
	mkdir $ROOT/lib/systemd/system/ -p

	sed -i "s/Version:.*/Version: $VER/" $ROOT/DEBIAN/control
	sed -i "s/Architecture:.*/Architecture: $ARCH/" $ROOT/DEBIAN/control
	chmod 0755 $ROOT/DEBIAN/prerm

	cp $SMARTDNS_DIR/etc/smartdns/smartdns.conf  $ROOT/etc/smartdns/
	cp $SMARTDNS_DIR/etc/default/smartdns  $ROOT/etc/default/
	cp $SMARTDNS_DIR/systemd/smartdns.service $ROOT/lib/systemd/system/ 
	cp $SMARTDNS_DIR/src/smartdns $ROOT/usr/sbin
	if [ $? -ne 0 ]; then
		echo "copy smartdns file failed."
		return 1
	fi
	chmod +x $ROOT/usr/sbin/smartdns

	dpkg -b $ROOT $OUTPUTDIR/smartdns.$VER.$FILEARCH.deb

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
