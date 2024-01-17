FROM golang:1.20-bookworm as builder
ARG VERSION="docker-latest"

WORKDIR /app
COPY . .
RUN go mod download

# Build the application as a static binary
# CGO_ENABLED=0 disables CGO, and -ldflags '-extldflags "-static"' tells the linker to produce a static binary
RUN CGO_ENABLED=0 go build -ldflags "-extldflags \"-static\" -X main.version=$VERSION" -o blackbox_http

# Start a new stage from scratch
FROM scratch
COPY --from=builder /app/blackbox_http /blackbox_http

ENV BLACKBOX_EXPORTER_AUTH="disabled"
ENV BLACKBOX_EXPORTER_HTTP_PORT="8080"
CMD ["/blackbox_http"]
