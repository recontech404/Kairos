FROM golang:1.23

RUN apt update && apt install gcc

ENV GOOS=linux
ENV GO111MODULE=auto
ENV CGO_ENABLED=1

WORKDIR /app
COPY ./ .

RUN go mod download && go build -o /app/main cmd/main.go

CMD ["/app/main"]