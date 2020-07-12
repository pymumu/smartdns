 FROM debian:buster-slim

 RUN apt update && \
     apt install -y git make gcc libssl-dev && \
     git clone https://github.com/pymumu/smartdns.git --depth 1 && \
     cd smartdns && \
     sh ./package/build-pkg.sh --platform debian --arch `dpkg --print-architecture` && \
     dpkg -i package/*.deb && \
     cd / && \
     rm -rf smartdns/ && \
     apt autoremove -y git make gcc libssl-dev && \
     apt clean && \
     rm -rf /var/lib/apt/lists/*

 EXPOSE 53/udp
 VOLUME "/etc/smartdns/"

 CMD ["/usr/sbin/smartdns", "-f"]
