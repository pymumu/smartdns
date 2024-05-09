FROM ubuntu:latest as smartdns-builder
LABEL previous-stage=smartdns-builder

# prepare builder
ARG OPENSSL_VER=3.0.10
RUN apt update && \
    apt install -y binutils perl curl make musl-tools musl-dev && \
    ln -s /usr/include/linux /usr/include/$(uname -m)-linux-musl && \
    ln -s /usr/include/asm-generic /usr/include/$(uname -m)-linux-musl && \
    ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/$(uname -m)-linux-musl && \
    \
    mkdir -p /build/openssl && \
    cd /build/openssl && \
    curl -sSL http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_${OPENSSL_VER}.orig.tar.gz | tar --strip-components=1 -zxv && \
    \
    export CC=musl-gcc && \
    if [ "$(uname -m)" = "aarch64" ]; then \
        ./config --prefix=/opt/build no-tests -mno-outline-atomics ; \
    else \ 
        ./config --prefix=/opt/build no-tests ; \
    fi && \
    make all -j8 && make install_sw && \
    cd / && rm -rf /build

# do make
COPY . /build/smartdns/
RUN cd /build/smartdns && \
    export CC=musl-gcc && \
    export CFLAGS="-I /opt/build/include" && \
    export LDFLAGS="-L /opt/build/lib -L /opt/build/lib64" && \
    sh ./package/build-pkg.sh --platform linux --arch `dpkg --print-architecture` --static && \
    \
    ( cd package && tar -xvf *.tar.gz && chmod a+x smartdns/etc/init.d/smartdns ) && \
    \
    mkdir -p /release/var/log /release/run && \
    cp package/smartdns/etc /release/ -a && \
    cp package/smartdns/usr /release/ -a && \
    cd / && rm -rf /build

FROM busybox:stable-musl
COPY --from=smartdns-builder /release/ /
EXPOSE 53/udp
VOLUME ["/etc/smartdns/"]

CMD ["/usr/sbin/smartdns", "-f", "-x"]
