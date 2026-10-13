# 基础镜像：Debian 版 Node
# 说明：Cloudflare 的 workerd 运行时依赖 glibc，不能用 Alpine(musl)，否则 wrangler dev 会启动失败
FROM node:20-slim

# 关闭 npm 交互提示与 wrangler 遥测，避免容器内阻塞等待输入
ENV CI=true \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    WRANGLER_SEND_METRICS=false

# 工作目录
WORKDIR /app

# 先复制依赖清单并安装，利用 Docker 层缓存（wrangler 在 devDependencies 中，这里需要一并安装）
COPY package.json ./
RUN npm install

# 复制项目其余文件（node_modules 等由 .dockerignore 排除，不会被覆盖）
COPY . .

# wrangler dev 默认只监听本地回环，必须放开到 0.0.0.0 才能被容器外访问
EXPOSE 8787

# 容器内以本地 workerd 运行时自托管启动
# 若设置了 SUB_ACCESS_TOKEN 环境变量则自动注入，未设置/为空时该段展开为空，行为等同于不带该参数
CMD ["sh", "-c", "exec npx wrangler dev --ip 0.0.0.0 --port 8787 ${SUB_ACCESS_TOKEN:+--var SUB_ACCESS_TOKEN:$SUB_ACCESS_TOKEN}"]
