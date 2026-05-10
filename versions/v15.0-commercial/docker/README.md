# WVS Docker 配置

## Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装依赖
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制代码
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wvs/ ./wvs/

# 暴露端口
EXPOSE 8080

# 启动命令
CMD ["python", "-m", "wvs", "server", "-p", "8080", "--host", "0.0.0.0"]
```

## docker-compose.yml

```yaml
version: '3.8'

services:
  wvs-master:
    build: .
    ports:
      - "8080:8080"
    environment:
      - WVS_MODE=master
      - WVS_DB_PATH=/data/wvs.db
    volumes:
      - ./data:/data
    command: python -m wvs server -p 8080 --host 0.0.0.0

  wvs-worker:
    build: .
    environment:
      - WVS_MODE=worker
      - WVS_MASTER_URL=http://wvs-master:8080
    depends_on:
      - wvs-master
    command: python -m wvs worker
    deploy:
      replicas: 3

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  redis_data:
```

## Kubernetes 配置

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wvs-master
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wvs-master
  template:
    metadata:
      labels:
        app: wvs-master
    spec:
      containers:
      - name: wvs
        image: wvs:latest
        ports:
        - containerPort: 8080
        env:
        - name: WVS_MODE
          value: "master"
---
apiVersion: v1
kind: Service
metadata:
  name: wvs-master
spec:
  selector:
    app: wvs-master
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wvs-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: wvs-worker
  template:
    metadata:
      labels:
        app: wvs-worker
    spec:
      containers:
      - name: wvs
        image: wvs:latest
        env:
        - name: WVS_MODE
          value: "worker"
        - name: WVS_MASTER_URL
          value: "http://wvs-master:8080"
```
