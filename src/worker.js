import { processAndRender, b64Encode } from './core.js';

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

  if (!nodeLinks.trim()) return jsonResponse({ ok: false, error: 'nodeLinks is required' }, 400);

  const inputKey = { nodeLinks, preferredIps, namePrefix, keepOriginalHost };
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
  const result = processAndRender({ ...inputKey, target });

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

    // 首页静态资源由 Workers Assets 自动处理
    // 兜底返回健康信息
    if (path === '/' || path === '') {
      // Assets 绑定会自动处理，但如果没有绑定 Assets 的话返回简单页
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>CF Sub</title></head><body><h1>CF Sub Worker OK</h1><p>请将 public 目录绑定为 Assets，或访问 /api/generate</p></body></html>`;
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/health') {
      return jsonResponse({ ok: true, time: Date.now() });
    }

    return new Response('Not Found', { status: 404 });
  },
};
