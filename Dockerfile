FROM golang:1.12 as builder
MAINTAINER Credit Kudos Engineering <engineering@creditkudos.com>

RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN GOOS=linux CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o main cmd/cli/main.go

FROM scratch
COPY --from=builder /build/main /bin/main
WORKDIR /work
ENTRYPOINT ["/bin/main"]
