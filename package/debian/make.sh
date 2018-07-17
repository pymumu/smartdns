#/bin/sh

CURR_DIR=`pwd`
VER="`date +"1.%Y.%m.%d-%H%M"`"
SMARTDNS_DIR=$CURR_DIR/../../
SMARTDNS_BIN=$SMARTDNS_DIR/src/smartdns
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
chmod 0755 $ROOT/DEBIAN/prerm

cp $SMARTDNS_DIR/etc/smartdns/smartdns.conf  $ROOT/etc/smartdns/
cp $SMARTDNS_DIR/etc/default/smartdns  $ROOT/etc/default/
cp $SMARTDNS_DIR/systemd/smartdns.service $ROOT/lib/systemd/system/ 
cp $SMARTDNS_DIR/src/smartdns $ROOT/usr/sbin
chmod +x $ROOT/usr/sbin/smartdns

dpkg -b $ROOT $CURR_DIR/smartdns.$VER.armhf.deb

rm -fr $ROOT/