#/bin/sh

CURR_DIR=`pwd`
VER="`date +"1.%Y.%m.%d-%H%M"`"
SMARTDNS_DIR=$CURR_DIR/../../
SMARTDNS_BIN=$SMARTDNS_DIR/src/smartdns
SMARTDNS_CONF=$SMARTDNS_DIR/etc/smartdns/smartdns.conf
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

sed -i "s/^\(bind .*\):53/\1:535/g" $ROOT/opt/etc/smartdns/smartdns.conf

cd $ROOT/control
chmod +x *
tar zcf ../control.tar.gz ./
cd $ROOT

tar zcf data.tar.gz opt
tar zcf $CURR_DIR/smartdns.$VER.mipsbig.ipk control.tar.gz data.tar.gz debian-binary
rm -fr $ROOT/