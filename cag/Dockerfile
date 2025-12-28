FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY . .

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o cag .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /src/cag .

CMD ["./cag"]
