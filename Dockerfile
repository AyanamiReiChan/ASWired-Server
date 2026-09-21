FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=development
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT}" -o /out/aswired-server ./cmd/aswired-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin aswired \
    && mkdir /data && chown 10001:10001 /data
COPY --from=build /out/aswired-server /usr/local/bin/aswired-server
USER 10001:10001
WORKDIR /data
ENV ASWIRED_DATA_DIR=/data ASWIRED_LISTEN=0.0.0.0:12889 ASWIRED_PUBLIC_URL=http://127.0.0.1:12889
VOLUME ["/data"]
EXPOSE 12889
ENTRYPOINT ["/usr/local/bin/aswired-server"]
CMD ["serve"]
