FROM alpine:3.5

RUN apk update && apk upgrade && apk add alpine-sdk

ADD ./ /src
WORKDIR /src

VOLUME [ "/src/build" ]

CMD make linux
