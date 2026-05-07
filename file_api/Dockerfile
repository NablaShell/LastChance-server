FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Статическая линковка для shred и других внешних вызовов
RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-w -s" -o /relay-file-node .

FROM alpine:latest
RUN apk add --no-cache ca-certificates coreutils
COPY --from=builder /relay-file-node /relay-file-node
EXPOSE 8081
# Тома для vault монтируются в docker-compose
ENTRYPOINT ["/relay-file-node"]
