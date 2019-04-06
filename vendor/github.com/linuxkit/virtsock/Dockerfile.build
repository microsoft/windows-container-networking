FROM golang:1.9.2-alpine3.7

# A container to build the sample Go code

RUN apk add --update build-base

ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The project sources
ADD ./ /go/src/github.com/linuxkit/virtsock
WORKDIR /go/src/github.com/linuxkit/virtsock

VOLUME [ "/go/src/github.com/linuxkit/virtsock/build" ]

CMD make build-binaries
