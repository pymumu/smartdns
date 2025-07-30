#!/bin/sh

CURR_DIR=$(cd $(dirname $0);pwd)
WORKDIR=$CURR_DIR/target
CODE_DIR="$CURR_DIR/.."
SMARTDNS_STATIC_DIR="$WORKDIR/smartdns-static"

main() {
    TARGET_DIR=$1
    PREFIX=$2
    if [ -z "$TARGET_DIR" ]; then
        echo "Usage: $0 <target_directory> [prefix_directory]"
        exit 1
    fi

    if [ ! -d "$TARGET_DIR" ]; then
        echo "Target directory $TARGET_DIR does not exist."
        exit 1
    fi


    if [ ! -f "$SMARTDNS_STATIC_DIR/smartdns" ]; then
        cp "$CODE_DIR/src/smartdns" "$TARGET_DIR$PREFIX/usr/sbin/smartdns"
        if [ $? -ne 0 ]; then
            echo "Failed to copy smartdns binary to $TARGET_DIR/usr/sbin."
            return 1
        fi

        chmod +x "$TARGET_DIR/usr/sbin/smartdns"

        return 0
    fi

    if [ ! -f "$SMARTDNS_STATIC_DIR/smartdns" ]; then
        echo "SmartDNS binary not found in $SMARTDNS_STATIC_DIR."
        return 1
    fi

    mkdir -p "$TARGET_DIR/usr/local/lib/smartdns"
    if [ $? -ne 0 ]; then
        echo "Failed to create directory $TARGET_DIR/usr/local/lib/smartdns."
        return 1
    fi

    cp $SMARTDNS_STATIC_DIR/* $TARGET_DIR/usr/local/lib/smartdns/ -a
    if [ $? -ne 0 ]; then
        echo "Failed to copy smartdns static files to $TARGET_DIR/usr/local/lib/smartdns."
        return 1
    fi

    ln -f -s "$PREFIX/usr/local/lib/smartdns/run-smartdns" "$TARGET_DIR/usr/sbin/smartdns"
    if [ $? -ne 0 ]; then
        echo "Failed to create symlink for smartdns in $TARGET_DIR/usr/sbin."
        return 1
    fi
    chmod +x "$TARGET_DIR/usr/local/lib/smartdns/run-smartdns"

    echo "SmartDNS files copied successfully to $TARGET_DIR."
    return 0
}

main $@
