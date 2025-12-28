# demo-CAM/CAG

> 本项目通过 Docker 模拟 IaaS 底层资源，并实现简化版 CAM（身份与授权）与 CAG（统一安全接入网关），
> 重点不是功能复杂度，而是 **用最小实现证明架构概念**：
> “谁 → 是否被允许 → 以统一方式 → 访问什么云资源 → 是否可审计”。


## 1. build

`docker compose up -d --build`

执行 `docker ps`确认下列container启动成功
```
node-1
node-2
cam-service
cag-gateway
```

## 2. test

1. Step 1 —— 登录请求 Token

```bash
curl -X POST http://localhost:9000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"123456"}'
```

复制 access_token

2. Step 2 —— 通过 CAG 访问 node-1/status

```bash
curl -X GET http://localhost:8000/nodes/node-1/status \
  -H "Authorization: Bearer <token>"
```

你应看到 node-1 正常返回：

```json
{
  "node": "node-1",
  "cpu_usage": 0.34,
  "mem_usage": 0.51
}
```

同时在 docker logs 里你能看到：

```bash
docker logs cag-gateway
```

你会看到 审计日志：

```vbnet
==== AUDIT LOG ====
time: 2025-...
user: alice
tenant: tenant-1
roles: ['ops']
node: node-1
action: status
status: 200
====================
```
这就是 合规审计能力。

3. Step 3 —— 通过 CAG 执行命令

```bash
curl -X POST http://localhost:8000/nodes/node-1/exec \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"echo hello"}'

```

应返回
```json
{
  "node": "node-1",
  "cmd": "echo hello",
  "result": "simulated result of `echo hello`",
  "status": "ok"
}

```

4. Step 4 —— 访问未授权节点

```bash
curl -X POST http://localhost:9000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"123456"}'

```

复制 bob token
尝试访问node-1

```
curl -X GET http://localhost:8000/nodes/node-1/status \
  -H "Authorization: Bearer <bob_token>"

```

预期结果：

```json
{
  "error": "access_denied",
  "node": "node-1"
}

```

## 3. 设计原则

在实现过程中我刻意遵守了三个设计原则：

1️⃣ 能映射真实 IaaS / 云治理环境  
- Node = 资源节点 / 计算节点
- CAM = IAM + 统一身份 / 授权中心
- CAG = 统一访问通道 + 强制策略执行点（Policy Enforcement Point）

2️⃣ 能体现真正 CAM / CAG 价值  
不仅仅是“能访问”，而是：
- 必须通过统一入口
- 必须携带身份与权限上下文
- 必须基于策略判断
- 必须可审计

3️⃣ 保持工程可运行、逻辑可解释  
所有逻辑都可以：
- 用 curl 演示
- 用日志证明
- 用代码说明

## 4. 能力对照

| 真实 IaaS / 企业系统 | 本 Demo 中的对应 |
|----------------------|------------------|
| 物理机 / 虚机 / 计算节点 | Docker Node Agent |
| 云平台统一 IAM / CAM | cam-service |
| 安全接入网关 / 零信任入口 / 堡垒机 | cag-gateway |
| 资源权限模型（租户 / 角色 / 资源范围） | JWT Claims（tenant / roles / allowed_nodes） |
| 强制访问控制（Policy Enforcement） | CAG 的 Token 校验 + 节点授权判断 |
| 运维审计与合规日志 | CAG Audit Logs |


http://localhost:8080/auth/login

http://localhost:8080/auth/roles

http://localhost:8080/auth/users

http://localhost:8080/auth/users/bob/roles