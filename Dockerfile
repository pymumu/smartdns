FROM ubuntu:latest as smartdns-builder
LABEL previous-stage=smartdns-builder
COPY . /smartdns/
RUN apt update && \
    apt install -y perl wget make musl-tools musl-dev && \
    OPENSSL_VER=1.1.1f && \
    mkdir /build -p && \
    ln -s /usr/include/linux /usr/include/$(uname -m)-linux-musl && \
    ln -s /usr/include/asm-generic /usr/include/$(uname -m)-linux-musl && \
    ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/$(uname -m)-linux-musl && \
    cd /build && \
    wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_${OPENSSL_VER}.orig.tar.gz && \
    tar xf openssl_${OPENSSL_VER}.orig.tar.gz && \
    cd openssl-${OPENSSL_VER} && \
    export CC=musl-gcc && \
    if [ "$(uname -m)" = "aarch64" ]; then \
        ./config --prefix=/opt/build no-tests -mno-outline-atomics ; \
    else \ 
        ./config --prefix=/opt/build no-tests; \
    fi && \
    make all -j8 && make install_sw && \
    cd /smartdns && \
    export CFLAGS="-I /opt/build/include" && \
    export LDFLAGS="-L /opt/build/lib" && \
    sh ./package/build-pkg.sh --platform linux --arch `dpkg --print-architecture` --static && \
    mkdir /release -p && \
    cd /smartdns/package && tar xf *.tar.gz && \
    cp /smartdns/package/smartdns/etc /release/ -a && \
    cp /smartdns/package/smartdns/usr /release/ -a && \
    chmod +x /release/etc/init.d/smartdns && \
    mkdir /release/var/log/ /release/var/run/ -p && \
    rm -fr /build /smartdns

FROM busybox:latest
COPY --from=smartdns-builder /release/ /
EXPOSE 53/udp
VOLUME "/etc/smartdns/"

CMD ["/usr/sbin/smartdns", "-f", "-x"]
