#!/bin/sh
# Copyright (C) 2018-2025 Nick Peng (pymumu@gmail.com)

CURR_DIR=$(cd $(dirname $0);pwd)
WORKDIR=$CURR_DIR/target
VER="`date +"1.%Y.%m.%d-%H%M"`"
CODE_DIR="$CURR_DIR/.."
IS_BUILD_SMARTDNS=1
OUTPUTDIR=$CURR_DIR
SMARTDNS_WEBUI_URL="https://github.com/pymumu/smartdns-webui/archive/refs/heads/main.zip"
SMARTDNS_WEBUI_SOURCE="$WORKDIR/smartdns-webui"
SMARTDNS_STATIC_DIR="$WORKDIR/smartdns-static"
SMARTDNS_WITH_LIBS=0
MAKE_NJOBS=1

export CC
export STRIP
export WORKDIR

WITH_UI=0

showhelp()
{
	echo "Usage: $0 [OPTION]"
	echo "Options:"
	echo " --platform [luci|luci-compat|debian|openwrt|optware|linux]    build for platform. "
	echo " --arch [all|armhf|arm64|x86-64|...]               build for architecture, e.g. "
	echo " --cross-tool [cross-tool]                         cross compiler, e.g. mips-openwrt-linux-"
	echo " --with-ui                                         build with smartdns-ui plugin."
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
	echo "   $0 --platform debian --arch arm64 --with-ui"
	echo " build optware mips:"
	echo "   $0 --platform optware --arch mipsbig"
	echo " build openwrt mips:"
	echo "   $0 --platform openwrt --arch mips"
	echo " build generic linux:"
	echo "   $0 --platform linux --arch x86-64 --with-ui"
}

init_env()
{
    if [ -z "$CC" ]; then
        CC=gcc
    fi

	MAKE_NJOBS=$(grep processor /proc/cpuinfo  | wc -l 2>/dev/null || echo 1)
	export MAKE_NJOBS

	mkdir -p $WORKDIR
	if [ $? -ne 0 ]; then
		echo "create work directory failed"
		return 1
	fi

	if [ "$STATIC" = "yes" ] && [ $WITH_UI -eq 1 ]; then
		SMARTDNS_WITH_LIBS=1
	fi

    check_cc="`echo "$CC" | grep -E "(\-gcc|\-cc)"`"
    if [ ! -z "$check_cc" ]; then
        TARGET_ARCH="`$CC -dumpmachine`"
        echo "target arch: $TARGET_ARCH"
    fi

    if [ $SMARTDNS_WITH_LIBS -eq 1 ]; then
		case "$TARGET_ARCH" in
			*arm*)
				NEED_UPDATE_ARM_CP15=1
				echo "Update arm cp15"
				;;
			*)
				;;
		esac

		LINKER_NAME=`$CC -Xlinker -v 2>&1 | grep -oP '(?<=-dynamic-linker )[^ ]+'`
		if [ -z "$LINKER_NAME" ]; then
			echo "get linker name failed"
			return 1
		fi
		LINKER_NAME=`basename $LINKER_NAME`
		LINKER_SYSROOT="`$CC --print-sysroot`"
		export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$LINKER_SYSROOT"
		echo "linker name: $LINKER_NAME"
	fi
}


copy_smartdns_libs()
{
	SMARTDNS_BIN="$CODE_DIR/src/smartdns"

    copy_libs_recursive $SMARTDNS_BIN
    if [ $? -ne 0 ]; then
        echo "copy libs failed"
        return 1
    fi

    LIB_WEBUI_SO="$CODE_DIR/plugin/smartdns-ui/target/smartdns_ui.so"
    copy_libs_recursive $LIB_WEBUI_SO
    if [ $? -ne 0 ]; then
        echo "copy libs failed"
        return 1
    fi
}

copy_libs_recursive()
{
    local lib=$1
    local lib_path=`$CC -print-file-name=$lib`
    if [ -z "$lib_path" ]; then
        return 0
    fi

    if [ -e $SMARTDNS_STATIC_DIR/lib/$lib ]; then
        return 0
    fi

    local tmp_path="`echo "$lib_path" | grep "libc.so"`"
    if [ ! -z "$tmp_path" ]; then
        LIBC_PATH="$tmp_path"
    fi

    if [ "$lib" != "$SMARTDNS_BIN" ]; then
        echo "copy $lib_path to $SMARTDNS_STATIC_DIR/lib"
        cp $lib_path $SMARTDNS_STATIC_DIR/lib
        if [ $? -ne 0 ]; then
            echo "copy $lib failed"
            return 1
        fi
    fi

    local shared_libs="`objdump -p $lib_path | grep NEEDED | awk '{print $2}'`"
    for sub_lib in $shared_libs; do
        copy_libs_recursive $sub_lib
        if [ $? -ne 0 ]; then
            return 1
        fi
    done

    return 0
}

copy_linker()
{
    LINK_PATH=`$CC -print-file-name=$LINKER_NAME`
    SYM_LINKER_NAME=`readlink -f $LINK_PATH`

    echo "linker: $LINK_PATH"
    echo "sym linker: $SYM_LINKER_NAME"
    echo "libc: $LIBC_PATH"

    if [ "$SYM_LINKER_NAME" = "$LIBC_PATH" ]; then
        ln -f -s $(basename $LIBC_PATH) $SMARTDNS_STATIC_DIR/lib/$(basename $LINKER_NAME)
    else
        cp $LINK_PATH $SMARTDNS_STATIC_DIR/lib -af
        if [ $? -ne 0 ]; then
            echo "copy $lib failed"
            return 1
        fi

        SYM_LINKER_NAME=`readlink $SMARTDNS_STATIC_DIR/lib/$LINKER_NAME`
        if [ ! -e $SMARTDNS_STATIC_DIR/lib/$SYM_LINKER_NAME ]; then
            SYM_LINKER_NAME=`basename $SYM_LINKER_NAME`
            ln -f -s $SYM_LINKER_NAME $SMARTDNS_STATIC_DIR/lib/$LINKER_NAME
        fi
    fi

    ln -f -s ${LINKER_NAME} ${SMARTDNS_STATIC_DIR}/lib/ld-linux.so
    if [ $? -ne 0 ]; then
        echo "copy $lib failed"
        return 1
    fi

    return 0
}

build_smartdns()
{
	MAKE_WITH_UI=""
	if [ $WITH_UI -eq 1 ]; then
		MAKE_WITH_UI="WITH_UI=1"
	fi

	if [ "$PLATFORM" = "luci" ]; then
		return 0
	fi

	make -C $CODE_DIR clean $MAKE_ARGS
	if [ $SMARTDNS_WITH_LIBS -eq 1 ]; then
		LINK_LDFLAGS='-Wl,-dynamic-linker,'lib/$(echo $LINKER_NAME)' -Wl,-rpath,\$$ORIGIN:\$$ORIGIN/lib'
		export LDFLAGS="$LDFLAGS $LINK_LDFLAGS"
		echo "LDFLAGS: $LDFLAGS"
		RUSTFLAGS='-C link-arg=-Wl,-rpath,$$ORIGIN'
		echo "Building smartdns with specific linker..."
		unset STATIC
	fi

	RUSTFLAGS="$RUSTFLAGS" make -C $CODE_DIR $MAKE_WITH_UI all -j$MAKE_NJOBS VER=$VER $MAKE_ARGS
	if [ $? -ne 0 ]; then
		echo "make smartdns failed"
		exit 1
	fi

	$STRIP -d $CODE_DIR/src/smartdns >/dev/null 2>&1

	rm -fr $SMARTDNS_STATIC_DIR
	if [ $SMARTDNS_WITH_LIBS -eq 0 ]; then
		return 0;
	fi

	echo "copy smartdns binary to $SMARTDNS_STATIC_DIR"
	mkdir -p $SMARTDNS_STATIC_DIR/lib
	if [ $? -ne 0 ]; then
		echo "create target directory failed"
		return 1
	fi

	cp $CODE_DIR/src/smartdns $SMARTDNS_STATIC_DIR/
	if [ $? -ne 0 ]; then
		echo "copy smartdns binary failed"
		return 1
	fi

	cp $CURR_DIR/run-smartdns $SMARTDNS_STATIC_DIR
	chmod +x $SMARTDNS_STATIC_DIR/run-smartdns
	if [ "$NEED_UPDATE_ARM_CP15" = "1" ]; then
        sed -i 's/NEED_CHECK_ARM_CP15=0/NEED_CHECK_ARM_CP15=1/' $SMARTDNS_STATIC_DIR/run-smartdns
        if [ $? -ne 0 ]; then
            echo "sed run-smartdns failed"
            return 1
        fi
    fi

	copy_smartdns_libs
	if [ $? -ne 0 ]; then
		echo "copy smartdns libs failed"
		return 1
	fi
	rm $SMARTDNS_STATIC_DIR/lib/smartdns_ui.so >/dev/null 2>&1

	copy_linker
    if [ $? -ne 0 ]; then
        echo "copy linker failed"
        return 1
    fi

	return 0
}

build_webpages()
{
	if [ ! -f "$WORKDIR/smartdns-webui.zip" ]; then
		echo "smartdns-webui source not found, downloading..."
		wget -O $WORKDIR/smartdns-webui.zip $SMARTDNS_WEBUI_URL
		if [ $? -ne 0 ]; then
			echo "Failed to download smartdns-webui source at $SMARTDNS_WEBUI_URL"
			return 1
		fi
	fi

	if [ ! -d "$SMARTDNS_WEBUI_SOURCE" ]; then
		echo "smartdns-webui source not found, unzipping..."
		unzip -q $WORKDIR/smartdns-webui.zip -d $WORKDIR
		if [ $? -ne 0 ]; then
			echo "Failed to unzip smartdns-webui source."
			return 1
		fi
		mv $WORKDIR/smartdns-webui-main $SMARTDNS_WEBUI_SOURCE
		if [ $? -ne 0 ]; then
			echo "Failed to rename smartdns-webui directory."
			return 1
		fi
	fi

	if [ ! -d "$SMARTDNS_WEBUI_SOURCE" ]; then
		echo "smartdns-webui source not found."
		return 1
	fi

	if [ ! -f "$SMARTDNS_WEBUI_SOURCE/package.json" ]; then
		echo "smartdns-webui source is not valid."
		return 1
	fi

	if [ -f "$SMARTDNS_WEBUI_SOURCE/out/index.html" ]; then
		echo "smartdns-webui already built, skipping build."
		return 0
	fi

	echo "Building smartdns-webui..."
	npm install --prefix $SMARTDNS_WEBUI_SOURCE
	if [ $? -ne 0 ]; then
		echo "Failed to install smartdns-webui dependencies."
		return 1
	fi

	npm run build --prefix $SMARTDNS_WEBUI_SOURCE
	if [ $? -ne 0 ]; then
		echo "Failed to build smartdns-webui."
		return 1
	fi

	echo "smartdns-webui build completed."

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

	WITH_UI_ARGS=""
	if [ $WITH_UI -eq 1 ] && [ "$PLATFORM" != "luci" ]; then
		build_webpages
		if [ $? -ne 0 ]; then
			echo "build smartdns-ui failed"
			return 1
		fi
		WITH_UI_ARGS="--with-ui"
	fi

	chmod +x $CODE_DIR/package/$PLATFORM/make.sh
	$CODE_DIR/package/$PLATFORM/make.sh -o $CURR_DIR --arch $ARCH --ver $VER --filearch $FILEARCH $WITH_UI_ARGS -o $OUTPUTDIR 
	if [ $? -ne 0 ]; then
		echo "build package for $PLATFORM failed"
		return 1
	fi

	echo "build package for $PLATFORM success."
	return 0
}

main()
{
	OPTS=`getopt -o o:h --long arch:,filearch:,ver:,platform:,cross-tool:,with-nftables,static,only-package,with-ui,outputdir: \
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
		--with-ui)
			WITH_UI=1
			shift 1;;
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

	init_env

	build
}

main $@
exit $?
