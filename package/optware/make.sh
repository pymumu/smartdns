#/bin/sh

CURR_DIR=`pwd`

SMARTDNS_BIN=$CURR_DIR/../../src/smartdns
SMARTDNS_CONF=$CURR_DIR/../../etc/smartdns/smartdns.conf
ROOT=/tmp/smartdns-optware
rm -fr $ROOT

mkdir -p $ROOT
cp * $ROOT/ -af
cd $ROOT/
mkdir $ROOT/opt/usr/sbin -p
mkdir $ROOT/opt/etc/init.d -p
mkdir $ROOT/opt/etc/smartdns/ -p

cp $SMARTDNS_CONF  $ROOT/opt/etc/smartdns/
cp S50smartdns $ROOT/opt/etc/init.d/
cp $SMARTDNS_BIN $ROOT/opt/usr/sbin

cd $ROOT/control
chmod +x *
tar zcf ../control.tar.gz ./
cd $ROOT

tar zcf data.tar.gz opt
tar zcf $CURR_DIR/smartdns.2018.7.6-1933.mipsbig.ipk control.tar.gz data.tar.gz debian-binary
rm -fr $ROOT/