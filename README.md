# webproxy

一个用 Go 写的网页整站反向代理工具。它把目标网站挂在你自己的域名路径前缀下，
并自动重写页面里出现的所有外部 URL，让整个站点（包括子域名和第三方资源）都
通过你的域名加载。

示例：用 `https://example.com` 反代 `https://claude.ai`

| 原始资源 | 反代后的 URL |
| --- | --- |
| `https://claude.ai/` | `https://example.com/claude.ai/` |
| `https://claude.ai/style.css` | `https://example.com/claude.ai/style.css` |
| `https://api.claude.ai/v1/test.js` | `https://example.com/api.claude.ai/v1/test.js` |

HTML、CSS、JavaScript、JSON 里的 URL 都会被自动重写。重写默认是**全量**的：
任何外部域名都会变成你域名下的一个路径前缀，除非你显式用 `-direct-domain`
排除，否则不会有流量直连真实源站。HTML 页面还会注入 `<base>` 标签，
让根路径相对 URL 也走反代。

WebSocket（`ws://` / `wss://`）也会被重写并转发，例如
`wss://ws.chatgpt.com/...` 变成 `wss://example.com/ws.chatgpt.com/...`。
上游 TLS 握手使用 Chrome 指纹（uTLS），ALPN 只提供 `http/1.1`，以便 CDN
（如 Cloudflare）协商 HTTP/1.1，协议升级请求可以正常穿透。

## 编译

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o dist/webproxy-linux-amd64 .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o dist/webproxy-windows-amd64.exe .
```

## 使用方法

```bash
webproxy -own-domain https://example.com -target https://claude.ai -listen :8080
```

参数说明：

- `-own-domain` — 你自己的域名（用于重写 URL），例如 `https://example.com`
- `-target` — 要反代的目标网站，例如 `https://claude.ai`
- `-listen` — 本地监听地址，例如 `:8080`
- `-bare-prefix` — 额外直连目标站根路径的前缀，默认 `/cdn-cgi/`
  （Cloudflare 验证页会用到）
- `-extra-domain` — 可选参数，仅为兼容保留。默认已经是全量重写，不再需要该参数
- `-direct-domain` — 逗号分隔的、**必须直连真实源站**的域名列表。
  只对确实无法反代的域名使用（例如脚本有来源校验、CDN 拒绝服务端请求）。
  `hcaptcha.com` 已默认直连，因为反代会弄坏验证码。
  另外 `w3.org`、`schema.org`、`react.dev` 等命名空间/文档类域名也默认直连：
  它们里面的 URL 是 URI 标识符（如 `http://www.w3.org/2000/svg`），重写会破坏
  React 的 SVG 命名空间处理导致页面崩溃，直连才是正确行为。
  注意：**不要**把 `sentinel.openai.com` 加进去，它的反爬 frame 是有意反代
  合成的，保证 `/backend-api/sentinel/req` 的请求留在你自己域名上。
- `-root-fallback` — 把没有路径前缀的路径反代到目标站（SPA 模式，默认 `true`）。
  claude.ai 这类前端路由应用依赖它（读取 `location.pathname`、请求根路径 API
  如 `/edge-api/...`）
- `-tls` — 用自动生成的自签证书提供 HTTPS（证书保存在二进制旁边的
  `webproxy-cert.pem` / `webproxy-key.pem`，之后会复用）
- `-cert` / `-key` — 使用你自己的 PEM 证书/私钥（必须成对提供，隐含 `-tls`）
- `-upstream-proxy` — 可选的上游代理，所有到目标站的 TCP 连接都会走它，
  格式 `socks5://host:port`、`socks5h://host:port`、`http://host:port` 或
  `https://host:port`（HTTP 代理支持 `http://user:pass@host:port` 基础认证）。
  适用场景：服务器自身 IP 被目标站的 Cloudflare / 机器人防护拦截（返回 403
  验证页），而你的另一台机器出口正常——把那台机器作为上游代理出口即可。
  SOCKS5 会把目标域名交给代理解析（远程 DNS），避免本地解析泄漏。uTLS
  Chrome 指纹和 HTTP/1.1 协商仍然生效，协议升级（WebSocket）也能正常穿透。

启动后打开 `https://example.com/claude.ai/` 即可访问。

本地纯 HTTP 测试：

```bash
webproxy -own-domain http://localhost:8080 -target https://claude.ai -listen :8080
# 打开 http://localhost:8080/claude.ai/
```

## 反代案例

### 反代 Claude（推荐命令）

Anthropic 的静态资源 CDN 会校验脚本的加载来源，反代 `assets-proxy.anthropic.com`
会导致登录页崩溃（React `flexShrink` 报错），所以要用 `-direct-domain` 排除：

```bash
webproxy -tls -own-domain https://example.com -target https://claude.ai -listen :443 \
  -direct-domain assets-proxy.anthropic.com
```

访问 `https://example.com/claude.ai/login`，登录、邮件验证码、AI 对话等流程
都会保持在 `example.com` 域名下。

### 反代 ChatGPT

ChatGPT 的登录流程会跳到 `auth.openai.com`，全量重写会自动把它反代成
`https://example.com/auth.openai.com/...`，无需额外参数：

```bash
webproxy -tls -own-domain https://example.com -target https://chatgpt.com -listen :443
```

- 登录链接（`auth.openai.com/...`）会自动反代为 `https://example.com/auth.openai.com/...`
- Sentinel 反爬 frame 及其 `/backend-api/sentinel/req` 请求也会经反代处理，
  不会泄漏到真实的 `sentinel.openai.com`

## 重要：路径前缀 vs 根站点模式

默认（不传 `-root-site`）时，目标站挂在你的域名**路径前缀**下
（`https://own/chatgpt.com/...`）。这对绝大多数普通网站没问题，但对
**现代 SPA**（ChatGPT、Claude 这类 Vite + React Router 应用）是脆弱的：
它们假设自己跑在域名根。路径前缀会让同一份 JS 模块（如 React）在
`/chatgpt.com/cdn/...` 和 `/cdn/...` 两个地址各加载一份，导致 React 上下文断裂
（控制台 `Cannot read properties of null (reading 'useContext')`），表现为侧边栏
点击 **图片 / 资料库 / 插件 / 项目** 出现 **Content failed to load**。

**推荐：给每个站用一个独立子域，开启 `-root-site`**——目标站直接挂在子域根、
无任何路径前缀，和 nginx `proxy_pass` 行为一致，SPA 完全按原生方式运行：

```bash
webproxy -tls -own-domain https://chatgpt.example.com -target https://chatgpt.com -listen :443 -root-site
```

访问 `https://chatgpt.example.com/`（直接是 ChatGPT 首页）。登录跳 `auth.openai.com`
仍会自动反代为 `https://chatgpt.example.com/auth.openai.com/...`（其它域保持前缀形式）。
建议 Caddy/Nginx 前端做 SSL 终止并反代到容器的 8080，如上面的 Compose 示例。

### 两种模式对比

- **默认（路径前缀）**：多个站共用一个域名/端口，按 `/host/` 区分；普通站可用，SPA 会有上述模块重复问题。
- **`-root-site`（根站点）**：一个子域反代一个目标站，挂在根路径；现代 SPA 推荐，问题最少。

## Docker 使用

每次 GitHub Release 会自动构建容器镜像并推送到仓库自带的容器仓库
（`ghcr.io/CangShui/webproxy`）。

### Docker Compose（推荐，Caddy 做 SSL 终止）

如果宿主机上已经部署 Caddy 处理 HTTPS，只需把 webproxy 放在 Caddy 后面，
让它监听一个内网端口即可，不占用宿主机的 80/443。

```yaml
services:
  webproxy:
    image: ghcr.io/cangshui/webproxy:latest
    container_name: webproxy
    restart: unless-stopped
    ports:
      - "127.0.0.1:17780:8080"
    # 根站点模式：ChatGPT 直接挂在 https://chatgpt.example.com 根路径，
    # 无 /chatgpt.com/ 前缀，SPA（侧边栏图片/资料库/插件/项目等）最稳。
    command:
      - -root-site
      - -own-domain
      - https://chatgpt.example.com
      - -target
      - https://chatgpt.com
      - -listen
      - :8080
    volumes:
      - webproxy-data:/app

volumes:
  webproxy-data:
```

Caddyfile 里加一条反代规则：

```caddyfile
chatgpt.example.com {
    reverse_proxy 127.0.0.1:17780
}
```

然后 `docker compose up -d` 启动，浏览器访问 `https://chatgpt.example.com/`（因为开了
`-root-site`，ChatGPT 直接挂在域名根，不再是 `/chatgpt.com/`）。
说明：

- `-own-domain` 必须用 `https://` 公网地址，这样重写出来的 URL 才是 https，
  避免混合内容被浏览器拦截
- `-listen :8080` 对应镜像默认端口，`ports` 映射成宿主机回环地址
  `127.0.0.1:17780`，只让 Caddy 访问
- `webproxy-data:/app` 命名卷用于在 `-tls` 模式下持久化自签证书（不用 `-tls` 时可去掉）
- 反代 ChatGPT 不需要 `-direct-domain`；只有反代 Claude 时才要加
  `-direct-domain assets-proxy.anthropic.com`


```bash
# 拉取最新镜像
docker pull ghcr.io/cangshui/webproxy:latest

# 运行（把参数换成你自己的域名 / 目标站）
docker run -d --name webproxy -p 443:443 -p 80:80 \
  ghcr.io/cangshui/webproxy \
  -tls -own-domain https://example.com -target https://claude.ai -listen :443 \
  -direct-domain assets-proxy.anthropic.com
```

- 容器以非 root 用户运行，工作目录 `/app` 可写，`-tls` 可以在里面生成并复用
  自签证书
- 在镜像名后面追加启动参数即可覆盖默认配置；也可以用 `-cert` / `-key`
  挂载你自己的证书
- 本地构建：`docker build -t webproxy .`

## 行为说明

- 路径前缀取自被反代的域名。目标站、它的子域名、同注册域名的兄弟子域名，
  以及其它任意外部域名都会被反代：`/claude.ai/...`、`/api.claude.ai/...`、
  `/assets-proxy.anthropic.com/...`。首段看起来像域名的路径会路由到该域名
- `localhost`、回环地址（`127.0.0.1`、`::1`）和单标签主机名（如 `intranet`）
  不会被反代，也不会被重写成代理路径，避免 `/localhost:3000/...` 这类上游
  dev 回跳地址变成代理上的 404
  （像 `robots.txt`、`app.js` 这种文件型首段会回落到目标站）
- 重定向保留查询参数，cookie 重新限定到你的域名（SPA 模式限定到根路径），
  Cloudflare 验证流程（`/?__cf_chl_rt_tk=...`、`/cdn-cgi/...`）可以正常通过
- SPA 模式：向目标页面注入脚本，在浏览器里去掉 URL 中的路径前缀，让前端路由
  匹配目标站原生路由。地址栏在首次跳转后会显示不带前缀的路径，这些路径由
  root fallback 反代，刷新和根路径 API 调用都能正常工作
- 每个页面都会注入运行时 shim，重写网站在 JS 里动态拼接的 URL：`a` 标签
  `href` 赋值和点击、`window.open`、`fetch`、`XMLHttpRequest`、表单提交
  （包括名为 `redirect_uri`、`next`、`callback` 等的隐藏输入）、
  `history.pushState` / `replaceState`。跨反代主机的历史跳转会转成真实整页跳转，
  模拟站点原本的跨域跳转
- OAuth 流程：值是 URL 的查询参数（`redirect_uri`、`return_to`、`callback` 等）
  会被重写，让浏览器一直留在反代域名上；转发请求前会恢复成原始值，授权服务器
  校验回调地址时仍然通过；授权服务器跳回回调地址时再重写回反代域名，
  整个登录流程都留在你的域名下
- 按 `Content-Type` 重写响应：HTML（属性、样式、`<base>`、meta refresh、
  srcset）、CSS（`url()` 和 `@import`）、JS/JSON（指向任何外部域名的绝对 URL）。
  JS/JSON 里的裸 `//host` 协议相对地址不重写（`//` 同时是注释和正则字面量语法，
  重写会破坏代码，例如 `/^https?:\/\//`），运行时 shim 会兜底处理
- `Link` 响应头（preload / preconnect 提示）也会像普通 URL 一样重写，避免浏览器
  直接请求未重写的提示地址
- 去掉 `Content-Security-Policy`、HSTS、`X-Frame-Options` 响应头
- cookie 重新限定到你的域名和反代路径前缀
- 移除 `integrity`（SRI）属性（因为响应内容被重写过）
- 根路径相对 URL（如表单 `action="/log-in/password"`）按当前页面的域名前缀重写，
  所以 `https://example.com/auth.openai.com/log-in/password` 上的表单仍然提交给
  `auth.openai.com`（而不是目标站）。重定向的 `Location` 头也按同样规则加前缀；
  相对地址留给浏览器按已反代的请求 URL 解析
- 请求头的 `Origin` / `Referer` 会改写成真实源站的来源（按反代页面推导），
  响应里的 `Access-Control-Allow-Origin` 回映成你的域名，目标的 CORS / CSRF
  校验和带凭证的 API 请求都能正常工作

## 故障排查

- Claude 登录页显示 "This page ran into a problem"（Frames SDK 报
  `Cannot set properties of undefined (setting 'flexShrink')`）：
  Anthropic 的资源 CDN 会校验脚本加载来源，用
  `-direct-domain assets-proxy.anthropic.com` 让它直连即可
- 密码登录即使 IP 干净也返回 HTTP 500：ChatGPT 的 `OpenAI-Sentinel-Token`
  证明和 sentinel SDK 的加载来源绑定。如果 `sentinel.openai.com` 被反代，
  SDK 看到的是反代后的 URL，服务端会拒绝该证明。请在真实浏览器里测试，
  不要把 `sentinel.openai.com` 加进 `-direct-domain`
- 无头 / 自动化浏览器（Playwright、Selenium、puppeteer）经常过不了
  Cloudflare / OpenAI 的机器人防护（`sec-ch-ua` 会暴露自动化特征）。
  这是上游行为，不是反代 bug，请使用普通浏览器

- 服务器上网页能打开、但首页 / 登录接口返回 Cloudflare 403 验证页：
  服务器 IP 被目标站防护拉黑。用一台出口干净的机器跑
  `-upstream-proxy socks5://127.0.0.1:1080`，并通过 SSH 反向隧道
  （`ssh -N -R 1080:127.0.0.1:1080`）把该机器的 SOCKS5 代理映射到服务器上，
  所有上游请求就从干净出口出去了
- 反代部署在 Caddy / nginx 之后（前级做 SSL 终止 + basic_auth，再
  `reverse_proxy` 到 webproxy），只有并发请求时上游静态资源（如
  `auth-cdn.oaistatic.com`）返回 Cloudflare WAF 403：这是前级附加的
  `Via` / `X-Forwarded-*` 代理链头 + basic_auth 的 `Authorization: Basic` 凭据
  被透传、触发上游 WAF。v0.1.9 起 webproxy 会自动剥掉这些前级代理链头
  （保留 `Bearer` 鉴权）并按上游域隔离 cookie，**无需改动前级配置**；
  升级镜像即可（`docker compose pull && docker compose up -d`）
- 前级 basic_auth 门禁下，登录完成、开始正常使用后浏览器反复弹出原生
  「用户名/密码」框、输对密码仍不断弹：浏览器只在顶层导航和子资源上
  附带缓存的 HTTP Basic 认证，**fetch()/XHR 请求不会附带**，于是前级对每条
  API 请求都返回 `401 WWW-Authenticate`。v0.1.10 起运行时 shim 会回放前级
  basic_auth 凭据到发往代理域的 fetch/XHR（只回放 `Basic`，不碰 `Bearer`，
  也不泄漏给直连域），**无需改动前级配置**；升级镜像即可
