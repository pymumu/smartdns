FROM ubuntu:latest as smartdns-builder

COPY . /smartdns/
RUN  apt update && \
     apt install -y make gcc libssl-dev && \
     cd smartdns && \
     sh ./package/build-pkg.sh --platform debian --arch `dpkg --print-architecture`

FROM ubuntu:latest
COPY --from=smartdns-builder /smartdns/package/*.deb /opt/
RUN dpkg -i /opt/*.deb && \
    rm /opt/*deb -fr

EXPOSE 53/udp
VOLUME "/etc/smartdns/"

CMD ["/usr/sbin/smartdns", "-f", "-x"]
