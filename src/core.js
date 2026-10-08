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
  const { keepOriginalHost = true, namePrefix = '' } = opts;
  const clone = JSON.parse(JSON.stringify(node));

  // 替换 address
  clone.address = ip.host;
  if (ip.port) clone.port = String(ip.port);

  // 处理 SNI / Host
  if (!keepOriginalHost) {
    clone.host = '';
    clone.sni = '';
  }

  // 名称前缀
  const baseName = clone.name || node.name || node.type;
  const ipTag = ip.remark || ip.host;
  const prefix = namePrefix ? `${namePrefix}-` : '';
  clone.name = `${prefix}${ipTag}-${baseName}`;

  return clone;
}

function generateNodes(nodeLinksText, preferredIpsText, opts = {}) {
  const nodes = parseNodeLinks(nodeLinksText);
  const ips = parsePreferredIps(preferredIpsText);
  const out = [];
  if (!ips.length) {
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
export function processAndRender(input) {
  const { nodeLinks, preferredIps, namePrefix = '', keepOriginalHost = true, target = 'raw' } = input;
  const nodes = generateNodes(nodeLinks, preferredIps, { namePrefix, keepOriginalHost });
  if (target === 'clash') return { nodes, text: renderClash(nodes), contentType: 'text/yaml; charset=utf-8' };
  if (target === 'surge') return { nodes, text: renderSurge(nodes), contentType: 'text/plain; charset=utf-8' };
  return { nodes, text: renderRaw(nodes), contentType: 'text/plain; charset=utf-8' };
}

export {
  parseNodeLinks,
  parsePreferredIps,
  generateNodes,
  renderRaw,
  renderClash,
  renderSurge,
  nodeToLink,
  b64Encode,
  b64Decode,
};
