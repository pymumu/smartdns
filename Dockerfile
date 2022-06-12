FROM ubuntu:latest as smartdns-builder

LABEL previous-stage=smartdns
COPY . /smartdns/
RUN  apt update && \
     apt install -y make gcc libssl-dev && \
     chmod -R 0755 smartdns && \
     cd smartdns && \
     sh ./package/build-pkg.sh --platform debian --arch `dpkg --print-architecture`

FROM ubuntu:latest
COPY --from=smartdns-builder /smartdns/package/*.deb /opt/
COPY --from=smartdns-builder /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/
COPY --from=smartdns-builder /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/
COPY --from=smartdns-builder /usr/lib/x86_64-linux-gnu/engines-1.1/* /usr/lib/x86_64-linux-gnu/engines-1.1/
RUN dpkg -i /opt/*.deb && \
    rm /opt/*deb -fr

EXPOSE 53/udp
VOLUME "/etc/smartdns/"

CMD ["/usr/sbin/smartdns", "-f", "-x"]
