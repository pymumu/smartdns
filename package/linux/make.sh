#!/bin/sh

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
	PKG_ROOT=/tmp/smartdns-linux
	rm -fr $PKG_ROOT
	mkdir -p $PKG_ROOT/smartdns
	cd $PKG_ROOT/

	# Generic x86_64
	mkdir $PKG_ROOT/smartdns/usr/sbin -p
	mkdir $PKG_ROOT/smartdns/package -p
	mkdir $PKG_ROOT/smartdns/systemd -p 
	
	cd $SMARTDNS_DIR
	cp package/windows $PKG_ROOT/smartdns/package/ -a
	cp etc *.md LICENSE package/linux/install $PKG_ROOT/smartdns/ -a
	cp systemd/smartdns.service $PKG_ROOT/smartdns/systemd
	cp src/smartdns $PKG_ROOT/smartdns/usr/sbin -a
	chmod +x $PKG_ROOT/smartdns/install

	if [ $? -ne 0 ]; then
		echo "copy smartdns file failed"
		rm -fr $PKG_ROOT
		exit 1
	fi
	cd $PKG_ROOT
	tar  zcf $OUTPUTDIR/smartdns.$VER.$FILEARCH.tar.gz smartdns
	if [ $? -ne 0 ]; then
		echo "create package failed"
		rm -fr $PKG_ROOT
		exit 1
	fi
	cd $CURR_DIR
	rm -fr $PKG_ROOT
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
