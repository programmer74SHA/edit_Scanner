FROM registry.apk-group.net/mirror/golang:1.23 AS builder
ENV GOPROXY="https://swap-repository.apk-group.net/go,direct"
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build \
    -ldflags="-s -w -X main.version=$(date +%Y%m%d-%H%M%S)" \
    -trimpath \
    -o asset_discovery_backend \
    cmd/asset_discovery/main.go

FROM registry.apk-group.net/mirror/alpine:3.22 AS runtime

# Set nmap version
ARG nmap_ver=7.95

# Install runtime dependencies for nmap and other tools
RUN apk add --update --no-cache \
    tzdata \
    iputils \
    openssl \
    ca-certificates \
    libgcc libstdc++ \
    libcrypto3 libssl3 \
    libpcap \
    libssh2 \
    lua5.4-libs \
    zlib \
 && update-ca-certificates

# Compile and install Nmap from sources
RUN apk add --update --no-cache --virtual .build-deps \
        linux-headers \
        openssl-dev \
        libpcap-dev \
        libssh2-dev \
        lua5.4-dev \
        pcre-dev \
        zlib-dev \
        autoconf automake g++ libtool make \
        curl \
    \
 && curl -fL -o /tmp/nmap.tar.bz2 \
         https://nmap.org/dist/nmap-${nmap_ver}.tar.bz2 \
 && tar -xjf /tmp/nmap.tar.bz2 -C /tmp \
 && cd /tmp/nmap* \
 && autoreconf libpcre libdnet-stripped -ivf \
 && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        --without-zenmap \
        --without-nmap-update \
        --with-liblua=/usr/lua5.4 \
        --with-libpcap=yes \
        --with-libpcre=yes \
        --with-libssh2=yes \
        --with-libz=yes \
        --with-openssl=yes \
 && make \
 && make install \
    \
 && apk del .build-deps \
 && rm -rf /var/cache/apk/* \
           /tmp/nmap*

ENV TZ=Asia/Tehran
RUN mkdir -p \
    /etc/siem/certs \
    /etc/siem/asset_discovery \
    /usr/share/siem/asset_discovery

RUN openssl req -x509 -nodes -days 365 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=SIEM/CN=localhost" \
    -newkey rsa:2048 \
    -keyout /etc/siem/certs/key.pem \
    -out /etc/siem/certs/cert.pem \
    -addext "subjectAltName=DNS:localhost,DNS:asset_discovery_backend,IP:127.0.0.1"

RUN addgroup -g 1001 -S siem && \
    adduser -u 1001 -S siem -G siem

WORKDIR /usr/share/siem/asset_discovery
COPY --from=builder --chown=siem:siem /app/asset_discovery_backend .
RUN chmod +x asset_discovery_backend && \
    chown -R siem:siem /etc/siem /usr/share/siem

#USER siem
USER root
EXPOSE 2030
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:2030/health || exit 1

ENTRYPOINT ["./asset_discovery_backend"]
CMD ["--config", "/etc/siem/asset_discovery/config.yml"]