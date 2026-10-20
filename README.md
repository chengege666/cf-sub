# CF Sub · 优选 IP 订阅器

轻量化的 Cloudflare Worker 优选 IP 订阅生成器。



## 一键部署

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/chengege666/cf-sub)

点击按钮 → 登录 Cloudflare → 授权 GitHub → 自动 Fork 仓库并部署 Worker。

> 注意：按钮部署不会自动创建 KV，部署完成后仍需按下方「快速开始」的第 3~4 步绑定 KV（`SUB_STORE`），否则短链功能不可用。



## 功能特性

- 协议：`vmess://` / `vless://` / `trojan://`
- Base64 订阅文本自动展开并识别节点
- 优选地址格式：`host[:port][#remark]`
- 相同输入 7 天内返回同一短链（KV TTL 去重）
- 访问令牌保护：`SUB_ACCESS_TOKEN`（可选）
- 导出格式：
  - `target=raw`：通用 Base64（默认）
  - `target=clash`：Clash YAML
  - `target=surge`：Surge 文本
- 前端能力：
  - 左右双栏，左侧输入 / 右侧结果
  - 节点 / 优选 IP 实时计数
  - 一键粘贴、导入 `.txt/.yaml/.conf` 文件
  - Tab 切换四种订阅（Auto / Raw / Clash / Surge）
  - 二维码扫码导入 + 一键复制
  - 本地保存前缀 / token / 开关（localStorage）
  - Toast 提示 + 状态条



## 快速开始

### 方式 A：Cloudflare Dashboard + GitHub 

1. 把本仓库代码推送到你自己的 GitHub 仓库
2. 打开 Cloudflare Dashboard → **Workers & Pages** → 创建 → **导入代码仓库**，选刚才那个仓库
   - 框架预设：`无（None）`
   - 构建命令：留空
   - 构建输出目录：留空
3. 到 **存储与数据库 → KV**，创建一个 KV 命名空间，名称建议 `SUB_STORE`
4. 回到刚才创建的 Worker → **设置 → 绑定 → 添加绑定**
   - 类型：`KV 命名空间`
   - 变量名称：必须填 `SUB_STORE`
   - KV 命名空间：选择上一步创建的那个，保存后重新部署
5. （可选）**设置 → 变量 → 机密变量（Secrets）** 里添加：
   - 变量名：`SUB_ACCESS_TOKEN`
   - 值：自定义的一串令牌
   - 设置后，访问 `/sub/:id` 必须携带 `?token=你的令牌`，否则会被拒绝
6. 重新部署一次，打开 Worker 分配的域名即可使用

### 方式 B：Cloudflare Pages（Continue with GitHub）

与方式 A 二选一即可，代码零改动（Pages 高级模式由 `public/_worker.js` 驱动）。

1. 打开 Cloudflare Dashboard → **Workers & Pages** → 创建 → **Pages** → **Connect to Git**（Continue with GitHub），授权并选择你的仓库
2. 构建配置（**只在第一次创建时填写，之后 push 自动部署，无需再填**）：
   - 框架预设：`无（None）`
   - 构建命令：留空
   - 构建输出目录：必须填 `public`（`_worker.js` 必须位于输出目录根部，高级模式才会生效）
3. 绑定 KV：项目 **设置 → 函数 → KV 命名空间绑定**，添加：
   - 变量名称：必须填 `SUB_STORE`
   - KV 命名空间：选择已创建的命名空间（注意绑定到**生产环境**）
4. （可选）**设置 → 环境变量** 里添加 `SUB_ACCESS_TOKEN`、`SUB_TTL_DAYS`（同样注意生产环境）
5. 部署完成后验证：打开 `https://<项目名>.pages.dev/` 应显示前端页面；`/health` 应返回 `{"ok":true,...}`

> 维护提醒：`public/_worker.js` 是自包含生成文件（内联了 `src/core.js`）。若修改了 `src/worker.js` 或 `src/core.js`，需同步重新生成 `public/_worker.js` 并推送，否则 Pages 跑的仍是旧逻辑。


## 环境变量 / Secrets

| 变量 | 位置 | 必填 | 说明 |
| --- | --- | --- | --- |
| `SUB_STORE` | KV binding | 是 | 保存短链记录，默认 7 天 TTL |
| `SUB_ACCESS_TOKEN` | Secret | 否 | 设置后 `/sub/:id` 和 `/api/raw` 都要带 `?token=` |
| `SUB_TTL_DAYS` | [vars] | 否 | 短链过期天数，默认 `7` |



## 注意事项

- 每条订阅记录默认保存 7 天（KV TTL）
- Surge 导出当前只包含 `vmess` / `trojan`
- 相同的 `{nodeLinks, preferredIps, namePrefix, keepOriginalHost}` 会命中 cache，返回同一短链
- Worker 的 `assets` 绑定会自动托管 `public/`，如果手动部署，记得 `wrangler.toml` 里的 `assets.directory = "public"`

## License

MIT
