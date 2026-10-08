# CF Sub · 优选 IP 订阅器

轻量化的 Cloudflare Worker 优选 IP 订阅生成器。
后端逻辑与 [cloudflaresub](https://github.com/InfiCheesy/cloudflaresub) 同源（节点解析 + KV 短链 + 多格式导出），
前端采用完全重写的 **玻璃拟态 UI**（左右分栏 + 毛玻璃卡片 + 渐变光晕 + Tab 切换 + 二维码）。

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

## 项目结构

```
cf-sub/
├─ src/
│  ├─ worker.js      # Worker 入口：/api/generate + /sub/:id + KV 短链
│  └─ core.js        # 节点解析 / 优选 IP 替换 / 多格式渲染
├─ public/           # 前端（玻璃拟态 UI，和原项目前端完全不同）
│  ├─ index.html
│  ├─ style.css
│  └─ app.js
├─ tests/smoke.mjs   # Node 端 smoke test
├─ wrangler.toml
└─ package.json
```

## 快速开始

### 方式 A：Cloudflare Dashboard + GitHub

1. 把本仓库推到你自己的 GitHub
2. Workers & Pages → **Create → Import a repository**，选这个仓库
   - Framework preset: None
   - Build command: 留空
   - Build output directory: 留空
3. 进入 **Storage & Databases → KV**，创建 Namespace，建议名 `SUB_STORE`
4. 回到 Worker → **Settings → Bindings → Add binding**
   - Type: `KV namespace`
   - Variable name: `SUB_STORE`
   - Namespace: 上一步创建的那个
5. （可选）**Settings → Variables → Secrets** 里添加：
   - Key: `SUB_ACCESS_TOKEN`
   - Value: 你自定的令牌
   - 配置后，访问 `/sub/:id` 必须带 `?token=...`
6. 重新部署，打开 Worker 域名即可使用



## 环境变量 / Secrets

| 变量 | 位置 | 必填 | 说明 |
| --- | --- | --- | --- |
| `SUB_STORE` | KV binding | 是 | 保存短链记录，默认 7 天 TTL |
| `SUB_ACCESS_TOKEN` | Secret | 否 | 设置后 `/sub/:id` 和 `/api/raw` 都要带 `?token=` |
| `SUB_TTL_DAYS` | [vars] | 否 | 短链过期天数，默认 `7` |

## 前端使用说明

1. 左侧粘贴节点或 Base64 订阅文本 → 自动识别节点数
2. 下方粘贴优选 IP（每行一条）
3. 设置前缀、是否保留 SNI、是否附带 token
4. 点 **✨ 生成订阅** → 右侧会出现短链 ID 和 4 个 Tab
5. 每个 Tab 都提供：订阅地址（可复制） + 二维码（扫码导入）
6. 左下角「复制全部链接」一次复制 4 个地址

## 注意事项

- 每条订阅记录默认保存 7 天（KV TTL）
- Surge 导出当前只包含 `vmess` / `trojan`
- 相同的 `{nodeLinks, preferredIps, namePrefix, keepOriginalHost}` 会命中 cache，返回同一短链
- Worker 的 `assets` 绑定会自动托管 `public/`，如果手动部署，记得 `wrangler.toml` 里的 `assets.directory = "public"`

## License

MIT
