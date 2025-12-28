# ===== 构建阶段：用 Go 镜像编译 =====
FROM golang:1.22-alpine AS builder

WORKDIR /src

# 一次性拷贝整个模块（包括 go.mod 和 main.go 等）
COPY . .

# 在构建容器内完成依赖解析 + 生成 go.sum
RUN go mod tidy

# 编译出静态二进制
RUN CGO_ENABLED=0 GOOS=linux go build -o cam .

# ===== 运行阶段：用精简运行镜像 =====
FROM alpine:3.20

WORKDIR /app

COPY --from=builder /src/cam .

CMD ["./cam"]
