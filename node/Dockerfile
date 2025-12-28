FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY . .

# 对 node 来说 go mod tidy 可有可无，如果没有 go.mod 就删掉这一行
# RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o node .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /src/node .

CMD ["./node"]
