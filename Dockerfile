FROM ubuntu:latest as smartdns-builder

RUN apt update && apt install -y libgtest-dev dnsperf make gcc g++ cmake openssl libssl-dev dnsutils
COPY . /app
WORKDIR /app
RUN make all -j$(nproc)

FROM ubuntu:latest
WORKDIR /usr/sbin/
COPY --from=smartdns-builder /app/src/smartdns ./
COPY --from=smartdns-builder /app/etc/smartdns/smartdns.conf /etc/smartdns/
EXPOSE 53/udp
VOLUME ["/etc/smartdns/"]

CMD ["smartdns", "-f", "-x"]
