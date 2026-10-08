(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const els = {
    nodeLinks: $('nodeLinks'),
    nodeMeta: $('nodeMeta'),
    preferredIps: $('preferredIps'),
    ipMeta: $('ipMeta'),
    namePrefix: $('namePrefix'),
    keepOriginalHost: $('keepOriginalHost'),
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
    history: 'cfsb.history_v1',
  };

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
        ta.style.top = '-9999px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
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
      els.btnCopyAllLinks.addEventListener('click', () => {
        const lines = [];
        if (els.linkAuto && els.linkAuto.value) lines.push('Auto  : ' + els.linkAuto.value);
        if (els.linkRaw && els.linkRaw.value) lines.push('Raw   : ' + els.linkRaw.value);
        if (els.linkClash && els.linkClash.value) lines.push('Clash : ' + els.linkClash.value);
        if (els.linkSurge && els.linkSurge.value) lines.push('Surge : ' + els.linkSurge.value);
        if (!lines.length) { toast('还没有链接'); return; }
        copyText(lines.join('\n')).then(() => toast('全部链接已复制 ✅')).catch(() => toast('复制失败'));
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
    const useToken = els.useLocalToken && els.useLocalToken.checked;
    const localToken = useToken ? (els.accessToken ? els.accessToken.value.trim() : '') : '';

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
        body: JSON.stringify({ nodeLinks, preferredIps, namePrefix, keepOriginalHost }),
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
