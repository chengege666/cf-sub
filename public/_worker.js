// === Pages 高级模式自包含版本：内联 src/core.js + src/worker.js，请勿手改，改 src 后重新生成 ===
// 节点解析与渲染核心函数
// 支持: vmess / vless / trojan

// ---------- Base64 工具 ----------
function b64Encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64Decode(str) {
  try {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch (e) {
    return '';
  }
}

function isLikelyBase64(s) {
  if (!s || s.length < 8) return false;
  const trimmed = s.trim().split(/\s+/).join('');
  if (!/^[A-Za-z0-9\-_=]+$/.test(trimmed)) return false;
  if (/^\d+$/.test(trimmed)) return false;
  const dec = b64Decode(trimmed);
  if (!dec) return false;
  if (!/[\x20-\x7E]/.test(dec)) return false;
  return (dec.includes('vmess://') || dec.includes('vless://') || dec.includes('trojan://') || dec.includes('ss://') || dec.includes('ssr://'));
}

function expandBase64(text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const out = [];
  for (const line of lines) {
    if (isLikelyBase64(line)) {
      const dec = b64Decode(line);
      if (dec) out.push(...dec.split(/\r?\n/).map(l => l.trim()).filter(Boolean));
    } else {
      out.push(line);
    }
  }
  return out;
}

// ---------- 协议解析 ----------
function parseVmessLink(link) {
  const prefix = 'vmess://';
  if (!link.startsWith(prefix)) return null;
  const payload = link.slice(prefix.length);
  const jsonStr = b64Decode(payload);
  if (!jsonStr) return null;
  let obj;
  try {
    obj = JSON.parse(jsonStr);
  } catch (e) {
    return null;
  }
  // 兼容 v2rayN 标准字段
  return {
    type: 'vmess',
    protocol: 'vmess',
    name: obj.ps || obj.name || 'vmess',
    uuid: obj.id,
    address: obj.add,
    port: String(obj.port),
    aid: String(obj.aid || 0),
    cipher: obj.scy || obj.type || 'auto',
    cipher_suite: obj.scy || 'auto',
    transport: obj.net || 'tcp',
    path: obj.path || '',
    host: obj.host || '',
    tls: (obj.tls === 'tls' || obj.tls === 'reality') ? 'tls' : '',
    sni: obj.sni || '',
    fp: obj.fp || '',
    pbk: obj.pbk || '',
    sid: obj.sid || '',
    alpn: obj.alpn || '',
    raw: link,
  };
}

function parseStandardLink(link, proto) {
  const prefix = proto + '://';
  if (!link.startsWith(prefix)) return null;
  const rest = link.slice(prefix.length);

  const hashIdx = rest.lastIndexOf('#');
  const remark = hashIdx >= 0 ? decodeURIComponent(rest.slice(hashIdx + 1)) : proto;
  const beforeHash = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;

  const qIdx = beforeHash.indexOf('?');
  const queryPart = qIdx >= 0 ? beforeHash.slice(qIdx + 1) : '';
  const authPart = qIdx >= 0 ? beforeHash.slice(0, qIdx) : beforeHash;

  // 可能包含 @ 连接: password@host:port 或者 uuid@host:port
  const atIdx = authPart.lastIndexOf('@');
  let cred = '';
  let addrPart = authPart;
  if (atIdx >= 0) {
    cred = authPart.slice(0, atIdx);
    addrPart = authPart.slice(atIdx + 1);
  }
  // 处理 [IPv6]:port
  let address = '';
  let port = '';
  if (addrPart.startsWith('[')) {
    const rb = addrPart.indexOf(']');
    if (rb >= 0) {
      address = addrPart.slice(1, rb);
      const after = addrPart.slice(rb + 1);
      if (after.startsWith(':')) port = after.slice(1);
    }
  } else {
    const ci = addrPart.lastIndexOf(':');
    if (ci >= 0) {
      address = addrPart.slice(0, ci);
      port = addrPart.slice(ci + 1);
    } else {
      address = addrPart;
    }
  }

  const query = new URLSearchParams(queryPart);
  const q = (k) => query.get(k) || '';

  const security = q('security');
  const tls = (security === 'tls' || security === 'reality') ? security : '';

  return {
    type: proto,
    protocol: proto,
    name: remark,
    uuid: proto === 'vless' ? cred : '',
    password: proto === 'trojan' ? cred : '',
    address: address,
    port: String(port || 443),
    cipher: q('encryption') || 'none',
    cipher_suite: q('encryption') || 'none',
    transport: q('type') || 'tcp',
    path: q('path') || q('serviceName') || '',
    host: q('host') || q('authority') || '',
    tls: tls,
    sni: q('sni') || '',
    fp: q('fp') || q('clientFingerprint') || '',
    pbk: q('pbk') || '',
    sid: q('sid') || '',
    alpn: q('alpn') || '',
    raw: link,
  };
}

function parseLink(line) {
  const l = line.trim();
  if (!l) return null;
  if (l.startsWith('vmess://')) return parseVmessLink(l);
  if (l.startsWith('vless://')) return parseStandardLink(l, 'vless');
  if (l.startsWith('trojan://')) return parseStandardLink(l, 'trojan');
  return null;
}

function parseNodeLinks(text) {
  const lines = expandBase64(text || '');
  const result = [];
  for (const line of lines) {
    const n = parseLink(line);
    if (n) result.push(n);
  }
  return result;
}

// ---------- 优选IP解析 ----------
function parsePreferredIpLine(line) {
  const s = line.trim();
  if (!s) return null;
  const hashIdx = s.lastIndexOf('#');
  const remark = hashIdx >= 0 ? s.slice(hashIdx + 1).trim() : '';
  const before = hashIdx >= 0 ? s.slice(0, hashIdx) : s;
  let host = before;
  let port = '';
  if (before.startsWith('[')) {
    const rb = before.indexOf(']');
    if (rb >= 0) {
      host = before.slice(1, rb);
      const after = before.slice(rb + 1);
      if (after.startsWith(':')) port = after.slice(1);
    }
  } else {
    const ci = before.lastIndexOf(':');
    if (ci >= 0) {
      host = before.slice(0, ci);
      port = before.slice(ci + 1);
    }
  }
  return { host: host.trim(), port: port.trim(), remark };
}

function parsePreferredIps(text) {
  if (!text) return [];
  return text.split(/\r?\n/).map(parsePreferredIpLine).filter(Boolean);
}

// ---------- 生成替换后的节点 ----------
function applyPreferredIp(node, ip, opts = {}) {
  const { keepOriginalHost = true, namePrefix = '', customPort = '' } = opts;
  const clone = JSON.parse(JSON.stringify(node));

  // 替换 address
  clone.address = ip.host;
  if (customPort) {
    clone.port = String(customPort);
  } else if (ip.port) {
    clone.port = String(ip.port);
  }

  // 处理 SNI / Host
  if (!keepOriginalHost) {
    clone.host = '';
    clone.sni = '';
  }

  // 名称前缀（不再包含优选IP）
  const baseName = clone.name || node.name || node.type;
  const prefix = namePrefix ? `${namePrefix}-` : '';
  clone.name = `${prefix}${baseName}`;

  return clone;
}

function generateNodes(nodeLinksText, preferredIpsText, opts = {}) {
  const { customPort = '' } = opts;
  const nodes = parseNodeLinks(nodeLinksText);
  const ips = parsePreferredIps(preferredIpsText);
  const out = [];
  if (!ips.length) {
    if (customPort) {
      return nodes.map(n => {
        const c = JSON.parse(JSON.stringify(n));
        c.port = String(customPort);
        return c;
      });
    }
    return nodes;
  }
  for (const n of nodes) {
    for (const ip of ips) {
      out.push(applyPreferredIp(n, ip, opts));
    }
  }
  return out;
}

// ---------- 导出: Raw (Base64) ----------
function nodeToLink(node) {
  if (node.protocol === 'vmess') {
    const obj = {
      v: '2',
      ps: node.name,
      add: node.address,
      port: node.port,
      id: node.uuid,
      aid: node.aid || '0',
      scy: node.cipher_suite || 'auto',
      net: node.transport || 'tcp',
      type: 'none',
      host: node.host || '',
      path: node.path || '',
      tls: node.tls || '',
      sni: node.sni || '',
      alpn: node.alpn || '',
      fp: node.fp || '',
    };
    if (node.tls === 'reality') {
      obj.pbk = node.pbk || '';
      obj.sid = node.sid || '';
    }
    return 'vmess://' + b64Encode(JSON.stringify(obj));
  }
  if (node.protocol === 'vless') {
    const query = new URLSearchParams();
    if (node.transport) query.set('type', node.transport);
    if (node.cipher && node.cipher !== 'none') query.set('encryption', node.cipher);
    if (node.tls) query.set('security', node.tls);
    if (node.sni) query.set('sni', node.sni);
    if (node.host) query.set('host', node.host);
    if (node.path) query.set('path', node.path);
    if (node.alpn) query.set('alpn', node.alpn);
    if (node.fp) query.set('fp', node.fp);
    if (node.pbk) query.set('pbk', node.pbk);
    if (node.sid) query.set('sid', node.sid);
    let addr = node.address;
    if (addr.includes(':')) addr = `[${addr}]`;
    return `vless://${encodeURIComponent(node.uuid)}@${addr}:${node.port}?${query.toString()}#${encodeURIComponent(node.name)}`;
  }
  if (node.protocol === 'trojan') {
    const query = new URLSearchParams();
    if (node.transport) query.set('type', node.transport);
    if (node.tls) query.set('security', node.tls);
    if (node.sni) query.set('sni', node.sni);
    if (node.host) query.set('host', node.host);
    if (node.path) query.set('path', node.path);
    if (node.alpn) query.set('alpn', node.alpn);
    if (node.fp) query.set('fp', node.fp);
    let addr = node.address;
    if (addr.includes(':')) addr = `[${addr}]`;
    return `trojan://${encodeURIComponent(node.password)}@${addr}:${node.port}?${query.toString()}#${encodeURIComponent(node.name)}`;
  }
  return '';
}

function renderRaw(nodes) {
  const links = nodes.map(nodeToLink).filter(Boolean);
  return b64Encode(links.join('\n'));
}

// ---------- 导出: Clash YAML ----------
function yamlEscape(s) {
  if (typeof s !== 'string') return s;
  if (/[:#&*!|>'"%@`\[\]{}]/.test(s) || /^\s|\s$/.test(s)) {
    return JSON.stringify(s);
  }
  return s;
}

function clashNode(node, idx) {
  const lines = [];
  const t = node.protocol;
  lines.push(`  - name: ${yamlEscape(node.name)}`);
  lines.push(`    type: ${t === 'vmess' ? 'vmess' : t === 'vless' ? 'vless' : 'trojan'}`);
  lines.push(`    server: ${yamlEscape(node.address)}`);
  lines.push(`    port: ${node.port}`);
  if (t === 'vmess') {
    lines.push(`    uuid: ${yamlEscape(node.uuid)}`);
    lines.push(`    alterId: ${node.aid || 0}`);
    lines.push(`    cipher: ${yamlEscape(node.cipher_suite || 'auto')}`);
  } else if (t === 'vless') {
    lines.push(`    uuid: ${yamlEscape(node.uuid)}`);
    if (node.cipher && node.cipher !== 'none') lines.push(`    cipher: ${yamlEscape(node.cipher)}`);
  } else if (t === 'trojan') {
    lines.push(`    password: ${yamlEscape(node.password)}`);
  }
  // UDP / TLS
  lines.push(`    udp: true`);
  if (node.tls === 'tls' || node.tls === 'reality') {
    lines.push(`    tls: true`);
  } else {
    lines.push(`    tls: false`);
  }
  if (node.sni) lines.push(`    sni: ${yamlEscape(node.sni)}`);
  if (node.alpn) {
    const parts = node.alpn.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length) lines.push(`    alpn: [${parts.map(p => yamlEscape(p)).join(', ')}]`);
  }
  // 传输层
  const net = node.transport || 'tcp';
  if (net === 'ws') {
    lines.push(`    network: ws`);
    const wsOpts = [];
    if (node.path) wsOpts.push(`      path: ${yamlEscape(node.path)}`);
    if (node.host) wsOpts.push(`      headers:`), wsOpts.push(`        Host: ${yamlEscape(node.host)}`);
    if (wsOpts.length) {
      lines.push(`    ws-opts:`);
      lines.push(...wsOpts);
    }
  } else if (net === 'grpc') {
    lines.push(`    network: grpc`);
    if (node.path) lines.push(`    grpc-opts:`), lines.push(`      grpc-service-name: ${yamlEscape(node.path)}`);
  } else if (net === 'h2' || net === 'http') {
    lines.push(`    network: h2`);
    if (node.path) lines.push(`    h2-opts:`), lines.push(`      path: ${yamlEscape(node.path)}`);
    if (node.host) {
      const hosts = node.host.split(',').map(s => s.trim()).filter(Boolean);
      if (hosts.length) {
        lines.push(`      host: [${hosts.map(h => yamlEscape(h)).join(', ')}]`);
      }
    }
  }
  // Reality
  if (node.tls === 'reality') {
    lines.push(`    reality-opts:`);
    if (node.fp) lines.push(`      client-fingerprint: ${yamlEscape(node.fp)}`);
    if (node.pbk) lines.push(`      public-key: ${yamlEscape(node.pbk)}`);
    if (node.sid) lines.push(`      short-id: ${yamlEscape(node.sid)}`);
  }
  if (node.fp && node.tls !== 'reality') {
    lines.push(`    client-fingerprint: ${yamlEscape(node.fp)}`);
  }
  return lines.join('\n');
}

function renderClash(nodes) {
  const out = [];
  out.push(`mixed-port: 7890`);
  out.push(`external-controller: 127.0.0.1:9090`);
  out.push(`allow-lan: false`);
  out.push(`mode: rule`);
  out.push(`log-level: info`);
  out.push(``);
  out.push(`proxies:`);
  const list = [];
  const names = [];
  for (let i = 0; i < nodes.length; i++) {
    list.push(clashNode(nodes[i], i));
    names.push(nodes[i].name);
  }
  out.push(list.join('\n'));
  out.push(``);
  out.push(`proxy-groups:`);
  out.push(`  - name: PROXY`);
  out.push(`    type: select`);
  out.push(`    proxies:`);
  for (const n of names) out.push(`      - ${yamlEscape(n)}`);
  out.push(``);
  out.push(`rules:`);
  out.push(`  - MATCH,PROXY`);
  return out.join('\n');
}

// ---------- 导出: Surge ----------
function surgeNode(node) {
  const t = node.protocol;
  const name = node.name;
  const server = node.address;
  const port = node.port;
  let line = '';
  if (t === 'vmess') {
    line = `${name} = vmess, ${server}, ${port}, username=${node.uuid}, ws=true`;
    if (node.transport === 'ws' && node.path) line += `, ws-path=${node.path}`;
    if (node.host) line += `, ws-headers=Host:${node.host}`;
    if (node.tls === 'tls') line += `, tls=true`;
    if (node.sni) line += `, sni=${node.sni}`;
    if (node.aid) line += `, alterId=${node.aid}`;
  } else if (t === 'trojan') {
    line = `${name} = trojan, ${server}, ${port}, password=${node.password}`;
    if (node.transport === 'ws') {
      line += `, ws=true`;
      if (node.path) line += `, ws-path=${node.path}`;
      if (node.host) line += `, ws-headers=Host:${node.host}`;
    }
    if (node.tls === 'tls') line += `, tls=true`;
    if (node.sni) line += `, sni=${node.sni}`;
  } else {
    return null;
  }
  return line;
}

function renderSurge(nodes) {
  const out = [];
  out.push(`[Proxy]`);
  for (const n of nodes) {
    const s = surgeNode(n);
    if (s) out.push(s);
  }
  out.push(``);
  out.push(`[Proxy Group]`);
  const names = nodes.map(n => n.name).join(', ');
  out.push(`Proxy = select, ${names}`);
  out.push(``);
  out.push(`[Rule]`);
  out.push(`FINAL,Proxy`);
  return out.join('\n');
}

// ---------- 主入口 ----------
function processAndRender(input) {
  const { nodeLinks, preferredIps, namePrefix = '', keepOriginalHost = true, customPort = '', target = 'raw' } = input;
  const nodes = generateNodes(nodeLinks, preferredIps, { namePrefix, keepOriginalHost, customPort });
  if (target === 'clash') return { nodes, text: renderClash(nodes), contentType: 'text/yaml; charset=utf-8' };
  if (target === 'surge') return { nodes, text: renderSurge(nodes), contentType: 'text/plain; charset=utf-8' };
  return { nodes, text: renderRaw(nodes), contentType: 'text/plain; charset=utf-8' };
}


const TTL_DEFAULT = 7 * 24 * 60 * 60;

function makeId(len = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  const arr = new Uint8Array(len);
  if (globalThis.crypto && crypto.getRandomValues) {
    crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < len; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  for (let i = 0; i < len; i++) s += chars[arr[i] % chars.length];
  return s;
}

function hashKey(input) {
  const s = JSON.stringify(input);
  let h1 = 0xdeadbeef ^ s.length, h2 = 0x41c6ce57 ^ s.length;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = (4294967296 * (2097151 & h2) + (h1 >>> 0));
  return n.toString(36);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    },
  });
}

function checkToken(env, url) {
  const token = env.SUB_ACCESS_TOKEN;
  if (!token) return true;
  const q = url.searchParams.get('token');
  if (q === token) return true;
  return false;
}

async function handleGenerate(request, env) {
  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'Method not allowed' }, 405);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ ok: false, error: 'Invalid JSON body' }, 400);
  }
  const nodeLinks = (body.nodeLinks || '').toString();
  const preferredIps = (body.preferredIps || '').toString();
  const namePrefix = (body.namePrefix || '').toString();
  const keepOriginalHost = body.keepOriginalHost !== false;
  const customPort = (body.customPort || '').toString();

  if (!nodeLinks.trim()) return jsonResponse({ ok: false, error: 'nodeLinks is required' }, 400);

  const inputKey = { nodeLinks, preferredIps, namePrefix, keepOriginalHost, customPort };
  const cacheKey = 'cache:' + hashKey(inputKey);

  const store = env.SUB_STORE;
  const ttlDays = parseInt(env.SUB_TTL_DAYS || '7', 10);
  const ttl = Math.max(1, ttlDays) * 24 * 60 * 60;

  let shortId = null;
  if (store) {
    try {
      shortId = await store.get(cacheKey);
    } catch (e) {
      shortId = null;
    }
  }

  if (!shortId) {
    shortId = makeId(10);
    if (store) {
      try {
        await store.put('sub:' + shortId, JSON.stringify(inputKey), { expirationTtl: ttl });
        await store.put(cacheKey, shortId, { expirationTtl: ttl });
      } catch (e) {
        // 写入失败继续返回短链，但不会持久化
      }
    }
  }

  const baseUrl = new URL(request.url);
  const base = `${baseUrl.origin}/sub/${shortId}`;
  const token = env.SUB_ACCESS_TOKEN ? `?token=${encodeURIComponent(env.SUB_ACCESS_TOKEN)}` : '';
  const tokQ = (extra) => {
    const glue = token ? '&' : '?';
    return `${base}${token}${extra ? glue + extra : ''}`;
  };

  return jsonResponse({
    ok: true,
    shortId,
    urls: {
      auto: tokQ(''),
      raw: tokQ('target=raw'),
      clash: tokQ('target=clash'),
      surge: tokQ('target=surge'),
    },
    input: { nodeLinks: b64Encode(nodeLinks).slice(0, 32) + '...', preferredIps: preferredIps.split(/\n/).length, namePrefix, keepOriginalHost },
  });
}

async function handleSub(params, request, env) {
  const url = new URL(request.url);
  if (!checkToken(env, url)) {
    return new Response('Unauthorized: invalid token', { status: 401 });
  }
  const id = params.id;
  if (!id) return new Response('Not found', { status: 404 });

  const store = env.SUB_STORE;
  let inputKey = null;
  if (store) {
    try {
      const raw = await store.get('sub:' + id);
      if (raw) inputKey = JSON.parse(raw);
    } catch (e) {
      inputKey = null;
    }
  }
  if (!inputKey) {
    return new Response('Subscription not found or expired', { status: 404 });
  }

  const target = url.searchParams.get('target') || 'raw';
  const result = processAndRender({ ...inputKey, customPort: inputKey.customPort || '', target });

  const disposition = target === 'clash'
    ? `attachment; filename="clash_${id}.yaml"`
    : target === 'surge'
    ? `attachment; filename="surge_${id}.conf"`
    : `attachment; filename="sub_${id}.txt"`;

  return new Response(result.text, {
    status: 200,
    headers: {
      'Content-Type': result.contentType,
      'Cache-Control': 'public, max-age=3600',
      'Content-Disposition': disposition,
    },
  });
}

async function handleRawSub(request, env) {
  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'Method not allowed' }, 405);
  const url = new URL(request.url);
  if (!checkToken(env, url)) {
    return new Response('Unauthorized: invalid token', { status: 401 });
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400);
  }
  const target = url.searchParams.get('target') || 'raw';
  const result = processAndRender({
    nodeLinks: body.nodeLinks || '',
    preferredIps: body.preferredIps || '',
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
    customPort: (body.customPort || '').toString(),
    target,
  });
  return new Response(result.text, {
    status: 200,
    headers: { 'Content-Type': result.contentType },
  });
}

function handleOptions() {
  return new Response('', {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Max-Age': '86400',
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return handleOptions();
    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path === '/api/generate') return handleGenerate(request, env);
    if (path === '/api/raw') return handleRawSub(request, env);

    // 订阅路由
    const subMatch = path.match(/^\/sub\/([A-Za-z0-9_-]+)$/);
    if (subMatch) return handleSub({ id: subMatch[1] }, request, env);

    // 首页：优先由 Pages 静态资产(index.html)提供服务，失败再回退到提示页
    if (path === '/' || path === '') {
      if (env.ASSETS) {
        try {
          return await env.ASSETS.fetch(request);
        } catch (e) {
          // 取资产失败，回退到简单提示页
        }
      }
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>CF Sub</title></head><body><h1>CF Sub Worker OK</h1><p>请将 public 目录绑定为 Assets，或访问 /api/generate</p></body></html>`;
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/health') {
      return jsonResponse({ ok: true, time: Date.now() });
    }

    // 其余路径：尝试静态资产(app.js/style.css 等)，未命中再返回 404
    if (env.ASSETS) {
      try {
        const assetRes = await env.ASSETS.fetch(request);
        if (assetRes && assetRes.status !== 404) return assetRes;
      } catch (e) {
        // 忽略，走 404
      }
    }
    return new Response('Not Found', { status: 404 });
  },
};
