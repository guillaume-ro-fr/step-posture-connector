# Build
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download
COPY internal ./internal/
COPY main.go ./

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go test -v ./...

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -o /step-posture-connector

# Run
FROM --platform=${BUILDPLATFORM:-linux/amd64} gcr.io/distroless/base-debian12:nonroot AS runner

WORKDIR /
COPY --from=builder /step-posture-connector /
USER nonroot:nonroot

EXPOSE 9443

CMD ["/step-posture-connector"]
