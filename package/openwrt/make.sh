#/bin/sh

CURR_DIR=$(cd $(dirname $0);pwd)

VER="`date +"1.%Y.%m.%d-%H%M"`"
SMARTDNS_DIR=$CURR_DIR/../../
SMARTDNS_BIN=$SMARTDNS_DIR/src/smartdns
SMARTDNS_CONF=$SMARTDNS_DIR/etc/smartdns/smartdns.conf
ADDRESS_CONF=$CURR_DIR/address.conf

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
    cp $CURR_DIR/files/etc $ROOT/root/ -af
    cp $SMARTDNS_BIN $ROOT/root/usr/sbin

    chmod +x $ROOT/root/etc/init.d/smartdns
    INST_SIZE="`du -sb $ROOT/root/ | awk '{print $1}'`"

    sed -i "s/^Architecture.*/Architecture: $ARCH/g" $ROOT/control/control
    sed -i "s/Version:.*/Version: $VER/" $ROOT/control/control
    sed -i "s/^\(bind .*\):53/\1:5353/g" $ROOT/root/etc/smartdns/smartdns.conf
    if [ ! -z "$INST_SIZE" ]; then
        echo "Installed-Size: $INST_SIZE" >> $ROOT/control/control
    fi

    cd $ROOT/control
    chmod +x *
    tar zcf ../control.tar.gz --owner=0 --group=0 ./
    cd $ROOT

    tar zcf $ROOT/data.tar.gz -C root --owner=0 --group=0 .
    tar zcf $OUTPUTDIR/smartdns.$VER.$ARCH.ipk --owner=0 --group=0 control.tar.gz data.tar.gz debian-binary
    rm -fr $ROOT/
}

main()
{
	OPTS=`getopt -o o:h --long arch:,ver: \
		-n  "" -- "$@"`

	if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

	# Note the quotes around `$TEMP': they are essential!
	eval set -- "$OPTS"

	while true; do
		case "$1" in
		--arch)
			ARCH="$2"
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

    if [ -z "$OUTPUTDIR" ]; then
        OUTPUTDIR=$CURR_DIR;
    fi

    build
}

main $@
exit $?


