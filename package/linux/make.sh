#!/bin/sh

CURR_DIR=$(cd $(dirname $0);pwd)
VER="`date +"1.%Y.%m.%d-%H%M"`"
SMARTDNS_DIR=$CURR_DIR/../../
SMARTDNS_CP=$SMARTDNS_DIR/package/copy-smartdns.sh
SMARTDNS_BIN=$SMARTDNS_DIR/src/smartdns
IS_BUILD_SMARTDNS_UI=0

showhelp()
{
	echo "Usage: make [OPTION]"
	echo "Options:"
	echo " -o               output directory."
	echo " --arch           archtecture."
	echo " --ver            version."
	echo " --with-ui        build with smartdns-ui plugin."
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

	$SMARTDNS_CP $PKG_ROOT/smartdns
	if [ $? -ne 0 ]; then
		echo "copy smartdns file failed."
		rm -fr $PKG_ROOT
		return 1
	fi

	if [ $IS_BUILD_SMARTDNS_UI -eq 1 ]; then
		mkdir $PKG_ROOT/smartdns/usr/local/lib/smartdns -p
		mkdir $PKG_ROOT/smartdns/usr/share/smartdns/wwwroot -p
		cp plugin/smartdns-ui/target/smartdns_ui.so $PKG_ROOT/smartdns/usr/local/lib/smartdns/smartdns_ui.so -a
		cp $WORKDIR/smartdns-webui/out/* $PKG_ROOT/smartdns/usr/share/smartdns/wwwroot/ -a
		if [ $? -ne 0 ]; then
			echo "Failed to copy smartdns-ui plugin."
			return 1
		fi
	else
		echo "smartdns-ui plugin not found, skipping copy."
	fi

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
	OPTS=`getopt -o o:h --long arch:,ver:,with-ui,filearch: \
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
		--with-ui)
			IS_BUILD_SMARTDNS_UI=1
			shift ;;
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
