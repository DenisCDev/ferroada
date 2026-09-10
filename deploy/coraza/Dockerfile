FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /coraza-sidecar .

FROM gcr.io/distroless/static-debian12
COPY --from=build /coraza-sidecar /coraza-sidecar
ENV WAF_SOCKET=/run/coraza/waf.sock
VOLUME /run/coraza
ENTRYPOINT ["/coraza-sidecar"]
