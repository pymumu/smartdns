FROM debian:buster-slim

RUN apt update && \
apt install -y git make gcc libssl-dev && \
    git clone https://github.com/pymumu/smartdns.git && \
    cd smartdns && \
    git checkout $(git describe --tags) && \
    sh ./package/build-pkg.sh --platform debian --arch `dpkg --print-architecture` && \
    dpkg -i package/*.deb && \
    cd / && \
    rm -rf smartdns/ && \
    apt purge -y --autoremove git make gcc libssl-dev && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 53/udp
VOLUME "/etc/smartdns/"

CMD /usr/sbin/smartdns && tail -f /var/log/smartdns.log 2>/dev/null
