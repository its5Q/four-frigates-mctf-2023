FROM golang:1.21

ARG FLAG
ENV FLAG=$FLAG

WORKDIR /usr/src/app

RUN apt update && apt install -y netcat-openbsd

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/app ./...

EXPOSE 1337

CMD ["app"]