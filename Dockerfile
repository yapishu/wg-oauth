FROM golang:1.22 as builder
WORKDIR /app
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/ .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
FROM debian:buster
RUN echo "deb http://deb.debian.org/debian buster-backports main non-free" >> /etc/apt/sources.list
RUN apt-get update && \
    apt-get install -y wireguard nftables && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/app .
CMD ["./app"]
