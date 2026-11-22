# syntax=docker/dockerfile:1

# Hybrid builder: if ./bin/lc-server exists (for example cross-compiled by
# deploy.sh), it is copied into the image. Otherwise the builder compiles the
# binary itself. The host binary must match the target architecture.
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN mkdir -p /out && if [ -f bin/lc-server ]; then \
        install -m 0755 bin/lc-server /out/lc-server; \
    else \
        CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lc-server ./cmd/lc-server; \
    fi

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S lc \
    && adduser -u 10001 -S -G lc -h /var/lib/lc-server -s /sbin/nologin lc \
    && mkdir -p /var/lib/lc-server \
    && chown -R lc:lc /var/lib/lc-server

COPY --from=builder /out/lc-server /usr/local/bin/lc-server

USER lc
EXPOSE 8080 8081
ENV LC_SERVER_CONFIG=/config/config.toml

ENTRYPOINT ["/usr/local/bin/lc-server"]
