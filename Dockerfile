FROM ubuntu:latest AS smartdns-builder
LABEL previous-stage=smartdns-builder

# prepare builder
ARG OPENSSL_VER=3.4.2
RUN apt update && \
    apt install -y binutils perl curl make gcc nodejs npm clang wget unzip ca-certificates && \
    update-ca-certificates && \
    \
    curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    \
    mkdir -p /build/openssl && \
    cd /build/openssl && \
    curl -sSL https://www.github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz | tar --strip-components=1 -zxv && \
    \
    OPENSSL_OPTIONS="no-argon2 no-aria no-async no-bf no-blake2 no-camellia no-cmp no-cms " \
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-comp no-des no-dh no-dsa no-ec2m no-engine no-gost "\
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-http no-idea no-legacy no-md4 no-mdc2 no-multiblock "\
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-nextprotoneg no-ocb no-ocsp no-rc2 no-rc4 no-rmd160 "\
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 "\
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-srp no-srtp no-ts no-whirlpool no-apps no-ssl-trace "\
    OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-ssl no-ssl3 no-tests -Os" \
    cd /build/openssl && \
    if [ "$(uname -m)" = "aarch64" ]; then \
        ./config --prefix=/opt/build $OPENSSL_OPTIONS -mno-outline-atomics ; \
    else \ 
        ./config --prefix=/opt/build $OPENSSL_OPTIONS ; \
    fi && \
    mkdir -p /opt/build/lib /opt/build/lib64 && \
    make all -j8 && make install_sw && \
    cd / && rm -rf /build

# do make
COPY . /build/smartdns/
RUN cd /build/smartdns && \
    export CFLAGS="-I /opt/build/include" && \
    export LDFLAGS="-L /opt/build/lib -L /opt/build/lib64" && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    rm -fr /build/smartdns/package/*.tar.gz && \
    sh ./package/build-pkg.sh --platform linux --arch `dpkg --print-architecture` --with-ui --static && \
    \
    ( cd package && tar -xvf *.tar.gz && chmod a+x smartdns/etc/init.d/smartdns ) && \
    \
    mkdir -p /release/var/log /release/run /release/var/lib/smartdns && \
    cp package/smartdns/etc /release/ -a && \
    cp package/smartdns/usr /release/ -a && \
    rm -f /release/usr/local/smartdns/lib/libssl* && \
    rm -f /release/usr/local/smartdns/lib/libcrypto* && \
    cp /opt/build/lib/lib*.so* /release/usr/local/lib/smartdns/lib/ -a 2>/dev/null || true && \
    cp /opt/build/lib64/lib*.so* /release/usr/local/lib/smartdns/lib/ -a 2>/dev/null || true && \
    cd / && rm -rf /build

FROM busybox:stable-musl
COPY --from=smartdns-builder /release/ /
EXPOSE 53/udp 6080/tcp
VOLUME ["/etc/smartdns/", "/var/lib/smartdns/"]

CMD ["/usr/sbin/smartdns", "-f", "-x"]
