FROM ubuntu:latest as smartdns-builder

COPY . /smartdns/
RUN apt-get update && \
    apt-get install -y make gcc libssl-dev && \
    cd smartdns && \
    sh ./package/build-pkg.sh --platform debian --arch `dpkg --print-architecture`

FROM ubuntu:latest
COPY --from=smartdns-builder /smartdns/package/*.deb /opt/
COPY docker-entrypoint.sh /entrypoint.sh
RUN dpkg -i /opt/*.deb && \
    rm /opt/*.deb -fr
RUN apt-get update \
  && apt-get install -y libssl1.1 \
  && apt autoremove \
  && apt autoclean \
  && rm -rf /tmp/*

EXPOSE 53/udp
VOLUME "/etc/smartdns/"

ENTRYPOINT ["/entrypoint.sh"]

CMD ["smartdns"]
