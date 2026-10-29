(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const els = {
    nodeLinks: $('nodeLinks'),
    nodeMeta: $('nodeMeta'),
    preferredIps: $('preferredIps'),
    ipMeta: $('ipMeta'),
    useBuiltinIp: $('useBuiltinIp'),
    namePrefix: $('namePrefix'),
    keepOriginalHost: $('keepOriginalHost'),
    customPort: $('customPort'),
    useLocalToken: $('useLocalToken'),
    tokenRow: $('tokenRow'),
    accessToken: $('accessToken'),
    btnPasteNodes: $('btnPasteNodes'),
    btnClearNodes: $('btnClearNodes'),
    btnLoadFile: $('btnLoadFile'),
    fileInput: $('fileInput'),
    btnGenerate: $('btnGenerate'),
    generateTip: $('generateTip'),
    statusPill: $('statusPill'),
    statusText: $('statusText'),
    resultEmpty: $('resultEmpty'),
    resultBody: $('resultBody'),
    shortId: $('shortId'),
    tabs: document.querySelectorAll('.tab'),
    linkAuto: $('linkAuto'),
    linkRaw: $('linkRaw'),
    linkClash: $('linkClash'),
    linkSurge: $('linkSurge'),
    qrAuto: $('qrAuto'),
    qrRaw: $('qrRaw'),
    qrClash: $('qrClash'),
    qrSurge: $('qrSurge'),
    btnCopyAllLinks: $('btnCopyAllLinks'),
    btnReset: $('btnReset'),
    alertBox: $('alertBox'),
    toast: $('toast'),
  };

  const QR_SERVER = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=0&data=';
  const LS = {
    token: 'cfsb.access_token',
    prefix: 'cfsb.name_prefix',
    keepHost: 'cfsb.keep_host',
    builtinIp: 'cfsb.use_builtin_ip',
    history: 'cfsb.history_v1',
  };

  // 最近一次成功生成时的输入快照，短链不可用时供 /api/raw 降级使用
  let lastGenInput = null;

  // 内置优选IP（已去重），每行一条，格式 host[:port][#remark]
  const BUILTIN_IPS = [
    '104.18.39.209',
    '104.18.36.122',
    '172.64.146.157',
    '172.64.148.133',
    '172.64.159.211',
    '104.18.8.147',
    '162.159.128.100',
    '104.19.152.161',
    '104.17.245.203',
    '104.17.112.221',
    '104.16.58.61',
    '104.26.4.247',
    '172.67.9.71',
    '103.172.110.230',
    '172.64.229.187',
    '172.64.154.228',
  ].join('\n');

  // ---------- 工具 ----------
  function toast(msg, ms = 1800) {
    if (!els.toast) return;
    els.toast.textContent = msg;
    els.toast.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => els.toast && els.toast.classList.remove('show'), ms);
  }

  function alertBox(type, msg) {
    const box = els.alertBox;
    if (!box) return;
    if (!type || !msg) {
      box.style.display = 'none';
      box.textContent = '';
      box.className = 'alert';
      return;
    }
    box.style.display = 'block';
    box.className = 'alert alert-' + type;
    box.textContent = msg;
  }

  function setStatus(kind, text) {
    const pill = els.statusPill;
    if (!pill) return;
    pill.classList.remove('success', 'error', 'info');
    if (kind) pill.classList.add(kind);
    if (els.statusText) els.statusText.textContent = text;
  }

  function copyText(text) {
    if (!text) return Promise.reject(new Error('empty'));

    // 传统复制兜底：Clipboard API 不可用或被拒绝时使用
    function legacyCopy() {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '0';
        ta.style.left = '-9999px';
        ta.style.width = '1px';
        ta.style.height = '1px';
        ta.style.padding = '0';
        ta.style.border = 'none';
        ta.style.outline = 'none';
        ta.style.boxShadow = 'none';
        ta.style.background = 'transparent';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        ta.setSelectionRange(0, ta.value.length);
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok ? Promise.resolve() : Promise.reject(new Error('execCommand failed'));
      } catch (e) {
        return Promise.reject(e);
      }
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(() => legacyCopy());
    }
    return legacyCopy();
  }

  // ---------- Base64 检测（简易） ----------
  function b64Decode(str) {
    try {
      let s = String(str).replace(/-/g, '+').replace(/_/g, '/').trim();
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) {
      return '';
    }
  }

  function splitLines(s) {
    return String(s || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  }

  function countNodes(text) {
    const lines = splitLines(text);
    // 检测首行是否为 base64 订阅：展开后再数
    if (lines.length === 1 && /^[A-Za-z0-9\-_=]+$/.test(lines[0]) && lines[0].length > 20) {
      const dec = b64Decode(lines[0]);
      if (dec && (dec.includes('vmess://') || dec.includes('vless://') || dec.includes('trojan://') || dec.includes('ss://'))) {
        return splitLines(dec).filter(l => /^((vmess|vless|trojan|ss|ssr):\/\/)/i.test(l)).length || splitLines(dec).length;
      }
    }
    return lines.filter(l => /^((vmess|vless|trojan|ss|ssr):\/\/)/i.test(l)).length || lines.length;
  }

  function countIps(text) {
    return splitLines(text).length;
  }

  function updateCounts() {
    els.nodeMeta.textContent = '共 ' + countNodes(els.nodeLinks.value) + ' 个节点';
    els.ipMeta.textContent = '共 ' + countIps(els.preferredIps.value) + ' 条';
  }

  // ---------- QR ----------
  function renderQr(container, text) {
    if (!container) return;
    container.innerHTML = '';
    if (!text) {
      const p = document.createElement('div');
      p.className = 'qr-placeholder';
      p.textContent = '生成后显示二维码';
      container.appendChild(p);
      return;
    }
    const img = document.createElement('img');
    img.alt = 'qrcode';
    img.loading = 'lazy';
    img.src = QR_SERVER + encodeURIComponent(text);
    img.onerror = () => {
      container.innerHTML = '<div class="qr-placeholder">二维码加载失败，可复制链接使用</div>';
    };
    container.appendChild(img);
  }

  // ---------- Tab ----------
  function bindTabs() {
    els.tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.target;
        els.tabs.forEach(t => t.classList.toggle('active', t === tab));
        document.querySelectorAll('.tab-panel').forEach(p => {
          p.classList.toggle('active', p.id === target);
        });
      });
    });
  }

  // ---------- 复制 ----------
  function bindCopyButtons() {
    document.querySelectorAll('.btn-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.target;
        const input = document.getElementById(id);
        if (!input || !input.value) {
          toast('还没有生成链接');
          return;
        }
        copyText(input.value).then(() => toast('已复制到剪贴板 ✅')).catch(() => toast('复制失败'));
      });
    });

    if (els.btnCopyAllLinks) {
      els.btnCopyAllLinks.addEventListener('click', async () => {
        const rawUrl = els.linkRaw && els.linkRaw.value ? els.linkRaw.value : '';
        if (!rawUrl) { toast('还没有生成链接'); return; }
        try {
          const resp = await fetch(rawUrl, { cache: 'no-store' });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          const txt = await resp.text();
          // target=raw 返回 Base64，解码为明文节点链接
          const plain = b64Decode(txt) || txt;
          if (!plain.trim()) { toast('节点链接为空'); return; }
          await copyText(plain);
          toast('全部节点链接已复制 ✅');
        } catch (shortErr) {
          // 短链不可用（如未绑定 KV）时，降级为实时渲染接口
          if (!lastGenInput) {
            toast('复制失败：' + (shortErr.message || '网络错误'));
            return;
          }
          try {
            const fallbackUrl = '/api/raw' + (lastGenInput.localToken
              ? '?token=' + encodeURIComponent(lastGenInput.localToken)
              : '');
            const fbResp = await fetch(fallbackUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                nodeLinks: lastGenInput.nodeLinks,
                preferredIps: lastGenInput.preferredIps,
                namePrefix: lastGenInput.namePrefix,
                keepOriginalHost: lastGenInput.keepOriginalHost,
                customPort: lastGenInput.customPort,
              }),
            });
            if (!fbResp.ok) throw new Error('HTTP ' + fbResp.status);
            const fbTxt = await fbResp.text();
            const fbPlain = b64Decode(fbTxt) || fbTxt;
            if (!fbPlain.trim()) { toast('节点链接为空'); return; }
            await copyText(fbPlain);
            toast('短链不可用，已实时生成并复制 ✅');
          } catch (e) {
            toast('复制失败：' + (e.message || '网络错误'));
          }
        }
      });
    }
  }

  // ---------- 粘贴 / 清空 / 文件 ----------
  function bindInputActions() {
    els.btnPasteNodes.addEventListener('click', async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const t = await navigator.clipboard.readText();
          els.nodeLinks.value = t;
          updateCounts();
          toast('已粘贴内容');
        } else {
          toast('浏览器不支持自动粘贴，请手动粘贴');
        }
      } catch (e) {
        toast('请手动粘贴到输入框');
      }
    });

    els.btnClearNodes.addEventListener('click', () => {
      els.nodeLinks.value = '';
      els.preferredIps.value = '';
      updateCounts();
      toast('已清空输入');
    });

    els.btnLoadFile.addEventListener('click', () => els.fileInput && els.fileInput.click());
    if (els.fileInput) {
      els.fileInput.addEventListener('change', () => {
        const f = els.fileInput.files && els.fileInput.files[0];
        if (!f) return;
        const reader = new FileReader();
        reader.onload = () => {
          const txt = String(reader.result || '');
          if (/^[A-Za-z0-9\-_=]+\s*$/.test(txt.trim()) && txt.trim().length > 20) {
            const dec = b64Decode(txt.trim());
            els.nodeLinks.value = (dec && dec.includes('://')) ? dec : txt;
          } else {
            els.nodeLinks.value = txt;
          }
          updateCounts();
          toast('已导入文件');
        };
        reader.onerror = () => toast('读取文件失败');
        reader.readAsText(f);
        els.fileInput.value = '';
      });
    }

    els.nodeLinks.addEventListener('input', updateCounts);
    els.preferredIps.addEventListener('input', updateCounts);

    // 内置IP联动：勾选后禁用输入框并填入内置IP，取消勾选恢复手填
    if (els.useBuiltinIp && els.preferredIps) {
      let lastManualIps = '';
      const syncBuiltin = (persist) => {
        const on = els.useBuiltinIp.checked;
        if (on) {
          lastManualIps = els.preferredIps.value;
          els.preferredIps.value = BUILTIN_IPS;
          els.preferredIps.disabled = true;
        } else {
          els.preferredIps.disabled = false;
          els.preferredIps.value = lastManualIps;
        }
        updateCounts();
        if (persist) try { localStorage.setItem(LS.builtinIp, on ? '1' : '0'); } catch (e) {}
      };
      els.useBuiltinIp.addEventListener('change', () => syncBuiltin(true));
      // 恢复上次勾选状态
      try {
        if (localStorage.getItem(LS.builtinIp) === '1') els.useBuiltinIp.checked = true;
      } catch (e) {}
      if (els.useBuiltinIp.checked) syncBuiltin(false);
    }

    if (els.useLocalToken) {
      const sync = () => {
        const on = els.useLocalToken.checked;
        els.tokenRow.style.display = on ? '' : 'none';
        if (on) try { localStorage.setItem(LS.token, els.accessToken.value || ''); } catch (e) {}
      };
      els.useLocalToken.addEventListener('change', sync);
      els.accessToken && els.accessToken.addEventListener('input', () => {
        if (els.useLocalToken.checked) try { localStorage.setItem(LS.token, els.accessToken.value || ''); } catch (e) {}
      });
      sync();
    }

    els.namePrefix && els.namePrefix.addEventListener('input', () => {
      try { localStorage.setItem(LS.prefix, els.namePrefix.value); } catch (e) {}
    });
    els.keepOriginalHost && els.keepOriginalHost.addEventListener('change', () => {
      try { localStorage.setItem(LS.keepHost, els.keepOriginalHost.checked ? '1' : '0'); } catch (e) {}
    });
  }

  function loadSavedPrefs() {
    try {
      const tok = localStorage.getItem(LS.token);
      if (tok !== null) {
        if (els.accessToken) els.accessToken.value = tok;
        if (els.useLocalToken) els.useLocalToken.checked = !!tok;
      }
      const pf = localStorage.getItem(LS.prefix);
      if (pf !== null && els.namePrefix) els.namePrefix.value = pf;
      const kh = localStorage.getItem(LS.keepHost);
      if (kh !== null && els.keepOriginalHost) els.keepOriginalHost.checked = kh !== '0';
      if (els.useLocalToken) {
        els.tokenRow.style.display = els.useLocalToken.checked ? '' : 'none';
      }
    } catch (e) {}
  }

  // ---------- 生成 ----------
  async function generate() {
    const nodeLinks = els.nodeLinks.value.trim();
    const preferredIps = els.preferredIps.value.trim();

    if (!nodeLinks) {
      alertBox('error', '请先粘贴节点链接或订阅内容');
      toast('节点内容不能为空');
      setStatus('error', '缺少节点');
      return;
    }

    const namePrefix = els.namePrefix ? els.namePrefix.value.trim() : '';
    const keepOriginalHost = !(els.keepOriginalHost && els.keepOriginalHost.checked === false);
    const customPort = els.customPort ? els.customPort.value.trim() : '';
    const useToken = els.useLocalToken && els.useLocalToken.checked;
    const localToken = useToken ? (els.accessToken ? els.accessToken.value.trim() : '') : '';

    // 保存本次生成的输入快照，供“复制全部链接”在短链失败时降级使用
    lastGenInput = { nodeLinks, preferredIps, namePrefix, keepOriginalHost, customPort, localToken };

    alertBox(null, null);
    setStatus('info', '生成中…');
    els.btnGenerate.classList.add('loading');
    els.btnGenerate.disabled = true;
    els.generateTip.textContent = '正在请求 Worker 生成短链订阅…';

    let data;
    try {
      const resp = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeLinks, preferredIps, namePrefix, keepOriginalHost, customPort }),
      });
      data = await resp.json();
      if (!resp.ok || !data.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    } catch (e) {
      els.btnGenerate.classList.remove('loading');
      els.btnGenerate.disabled = false;
      els.generateTip.textContent = '数据仅用于 Worker 生成短链，保存 7 天后自动失效';
      setStatus('error', '失败');
      alertBox('error', '生成失败：' + (e.message || '网络错误'));
      toast('生成失败 ❌');
      return;
    }

    // 拼装返回链接（若用户本地有 token，附带到链接）
    const urls = data.urls || {};
    const attach = (u) => {
      if (!u) return '';
      if (!useToken || !localToken) return u;
      try {
        const up = new URL(u, window.location.origin);
        if (!up.searchParams.has('token')) up.searchParams.set('token', localToken);
        return up.toString();
      } catch (e) { return u; }
    };

    const auto = attach(urls.auto || '');
    const raw = attach(urls.raw || '');
    const clash = attach(urls.clash || '');
    const surge = attach(urls.surge || '');

    els.resultEmpty.style.display = 'none';
    els.resultBody.style.display = '';
    if (els.shortId) els.shortId.textContent = data.shortId || '-';

    els.linkAuto.value = auto;
    els.linkRaw.value = raw;
    els.linkClash.value = clash;
    els.linkSurge.value = surge;

    renderQr(els.qrAuto, auto);
    renderQr(els.qrRaw, raw);
    renderQr(els.qrClash, clash);
    renderQr(els.qrSurge, surge);

    // 历史记录
    try {
      const arr = JSON.parse(localStorage.getItem(LS.history) || '[]');
      const record = {
        at: Date.now(),
        shortId: data.shortId,
        nodeCount: countNodes(nodeLinks),
        ipCount: countIps(preferredIps),
        auto,
      };
      arr.unshift(record);
      localStorage.setItem(LS.history, JSON.stringify(arr.slice(0, 8)));
    } catch (e) {}

    setStatus('success', '生成成功');
    alertBox('success', '订阅生成完成！请根据客户端选择对应格式。7 天内相同输入会返回同一短链。');
    toast('订阅生成成功 🎉');

    els.btnGenerate.classList.remove('loading');
    els.btnGenerate.disabled = false;
    els.generateTip.textContent = '数据仅用于 Worker 生成短链，保存 7 天后自动失效';
  }

  function bindGenerate() {
    els.btnGenerate.addEventListener('click', generate);
    if (els.btnReset) els.btnReset.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      els.nodeLinks.focus();
    });
  }

  // ---------- 初始化 ----------
  function init() {
    loadSavedPrefs();
    bindTabs();
    bindCopyButtons();
    bindInputActions();
    bindGenerate();
    updateCounts();
    // 二维码占位
    [els.qrAuto, els.qrRaw, els.qrClash, els.qrSurge].forEach(q => renderQr(q, ''));
    setStatus('', '待生成');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
