# PMT-DFC VPS tunnel-node Docker image.
#
# Build:
#   docker build -t pmt-server -f deploy/Dockerfile .
#
# Run:
#   docker run -d --name pmt-server \
#     -p 8080:8080 \
#     -e PMT_AUTH_KEY=your-secret-key-here \
#     pmt-server

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /pmt-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /pmt-server /pmt-server
EXPOSE 8080
ENTRYPOINT ["/pmt-server"]
