FROM golang:1.22-alpine

WORKDIR /app

# 一次性把当前服务的所有源码和配置都复制进来
COPY . .

# 如果 go.mod 不存在就 init，有的话这条命令会失败但被 || true 吃掉
RUN go mod init cam || true

# 根据 main.go 里的 import 自动分析依赖、生成 go.mod / go.sum
RUN go mod tidy

# 编译二进制
RUN go build -o cam .

CMD ["./cam"]
