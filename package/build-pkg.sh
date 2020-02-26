#!/bin/sh
# Copyright (C) 2018-2019 Nick Peng (pymumu@gmail.com)

CURR_DIR=$(cd $(dirname $0);pwd)
VER="`date +"1.%Y.%m.%d-%H%M"`"
CODE_DIR="$CURR_DIR/.."
IS_BUILD_SMARTDNS=1
OUTPUTDIR=$CURR_DIR
export CC
export STRIP

showhelp()
{
	echo "Usage: $0 [OPTION]"
	echo "Options:"
	echo " --platform [luci|luci-compat|debian|openwrt|optware|linux]    build for platform. "
	echo " --arch [all|armhf|arm64|x86-64|...]               build for architecture, e.g. "
	echo " --cross-tool [cross-tool]                         cross compiler, e.g. mips-openwrt-linux-"
	echo ""
	echo "Advance Options:"
	echo " --static                                          static link smartdns"
	echo " --only-package                                    only package, not build source"
	echo " --filearch [arch]                                 output file arch, default: equal --arch"
	echo " --outputdir [dir]                                 output package to specific directory"
	echo " "
	echo "Example:"
	echo " build luci:"
	echo "   $0 --platform luci"
	echo " build luci:"
	echo "   $0 --platform luci-compat"
	echo " build debian:"
	echo "   $0 --platform debian --arch x86-64"
	echo " build raspbian pi:"
	echo "   $0 --platform debian --arch armhf"
	echo " build optware mips:"
	echo "   $0 --platform optware --arch mipsbig"
	echo " build openwrt mips:"
	echo "   $0 --platform openwrt --arch mips_24kc"
	echo " build generic linux:"
	echo "   $0 --platform linux --arch x86-64"
}

build_smartdns()
{
	if [ "$PLATFORM" != "luci" ]; then
		make -C $CODE_DIR clean $MAKE_ARGS
		make -C $CODE_DIR all -j8 VER=$VER $MAKE_ARGS
		if [ $? -ne 0 ]; then
			echo "make smartdns failed"
			exit 1
		fi
	fi

	$STRIP -d $CODE_DIR/src/smartdns >/dev/null 2>&1

	return 0
}


build()
{
	echo "build package for $PLATFORM"

	if [ $IS_BUILD_SMARTDNS -eq 1 ]; then
		build_smartdns
		if [ $? -ne 0 ]; then
			return 1
		fi
	fi

	chmod +x $CODE_DIR/package/$PLATFORM/make.sh
	$CODE_DIR/package/$PLATFORM/make.sh -o $CURR_DIR --arch $ARCH --ver $VER --filearch $FILEARCH -o $OUTPUTDIR
	if [ $? -ne 0 ]; then
		echo "build package for $PLATFORM failed"
		return 1
	fi

	echo "build package for $PLATFORM success."
	return 0
}

main()
{
	OPTS=`getopt -o o:h --long arch:,filearch:,ver:,platform:,cross-tool:,static,only-package,outputdir: \
		-n  "" -- "$@"`

	if [ "$#" -le "1" ]; then
		showhelp
		exit 1
	fi

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
		--platform)
			PLATFORM="$2"
			shift 2;;
		--cross-tool)
			CROSS_TOOL="$2"
			shift 2;;
		--static)
			export STATIC="yes"
			shift 1;;
		--only-package)
			IS_BUILD_SMARTDNS=0
			shift 1;;
		--outputdir)
			OUTPUTDIR="$2"
			shift 2;;
		--ver)
			VER="$2"
			shift 2;;
		-h | --help )
			showhelp
			return 0
			shift ;;
		-- ) shift; break ;;
		* ) break ;;
		esac
	done

	if [ -z "$PLATFORM" ]; then
		echo "please input platform"
		echo "run $0 -h for help."
		return 1
	fi
	
	if [ "$PLATFORM" = "luci" ]; then
		ARCH="all"
	fi

	if [ -z "$ARCH" ]; then
		echo "please input arch."
		echo "run $0 -h for help."
		return 1
	fi

	if [ -z "$FILEARCH" ]; then 
		FILEARCH="$ARCH"
	fi

	if [ -z "$OUTPUTDIR" ]; then
		OUTPUTDIR=$CURR_DIR
	fi

	if [ ! -z "$CROSS_TOOL" ]; then
		CC="${CROSS_TOOL}gcc"
		STRIP="${CROSS_TOOL}strip"
	fi

	if [ -z "$CC" ]; then
		CC="gcc"
	fi

	if [ -z "$STRIP" ]; then
		if [ ! -z "`echo $CC | grep '\-gcc'`" ]; then
			STRIP="`echo "$CC" | sed 's/-gcc\$/-strip/g'`"
		else
			STRIP="strip"
		fi
	fi

	if [ ! -e "`which $CC`" ]; then
		echo "Cannot find compiler $CC"
		return 1
	fi

	build
}

main $@
exit $?
