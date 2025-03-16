FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o scanner ./main.go

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install --no-install-recommends --yes \
        ca-certificates \
        clamdscan \
        clamav-daemon \
        clamav-freshclam \
        libclamunrar \
        unrar

RUN freshclam

WORKDIR /app

COPY --chmod=744 --from=builder /app/scanner .

EXPOSE 8080
ENTRYPOINT service clamav-daemon start && /bin/bash -c ./scanner
