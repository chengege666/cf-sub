import {
  parseNodeLinks,
  parsePreferredIps,
  generateNodes,
  renderRaw,
  renderClash,
  renderSurge,
  processAndRender,
  b64Encode,
  b64Decode,
} from '../src/core.js';

function test(name, cond) {
  const mark = cond ? '✅' : '❌';
  console.log(`${mark} ${name}`);
  if (!cond) process.exitCode = 1;
}

// 测试 vmess
const sampleVmess = 'vmess://' + b64Encode(JSON.stringify({
  v: '2', ps: 'HK-Test', add: 'orig.example.com', port: 443,
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', aid: '0', scy: 'auto',
  net: 'ws', type: 'none', host: 'sni.example.com',
  path: '/ws', tls: 'tls', sni: 'sni.example.com',
}));

// 测试 vless
const sampleVless = `vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@orig.example.com:443?security=tls&sni=sni.example.com&type=ws&path=/ws&host=sni.example.com&alpn=h2,http/1.1&fp=chrome#VLESS-Test`;

// 测试 trojan
const sampleTrojan = `trojan://mypassword@orig.example.com:443?security=tls&sni=sni.example.com&type=tcp#Trojan-Test`;

const nodeLinks = [sampleVmess, sampleVless, sampleTrojan].join('\n');
const preferredIps = `104.16.1.2#HK\n104.17.2.3:2053#US`;

const parsedNodes = parseNodeLinks(nodeLinks);
test('parseNodeLinks: 解析出 3 个节点', parsedNodes.length === 3);
test('解析 vmess ps 正确', parsedNodes[0].name === 'HK-Test');
test('解析 vless uuid 正确', parsedNodes[1].uuid === 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
test('解析 trojan password 正确', parsedNodes[2].password === 'mypassword');

const ips = parsePreferredIps(preferredIps);
test('parsePreferredIps: 解析出 2 条优选', ips.length === 2);
test('优选第一条 host 正确', ips[0].host === '104.16.1.2' && ips[0].remark === 'HK');
test('优选第二条 host:port 正确', ips[1].host === '104.17.2.3' && ips[1].port === '2053');

const gen = generateNodes(nodeLinks, preferredIps, { namePrefix: 'CF', keepOriginalHost: true });
test('生成节点数 3*2 = 6', gen.length === 6);
test('替换后 address 为优选IP', gen[0].address === '104.16.1.2');
test('替换后 port 正确（含 port 的IP）', gen[1].port === '2053' && gen[3].port === '2053');
test('不带 port 的IP保持原端口', gen[0].port === '443' && gen[2].port === '443');
test('保留 SNI', gen[0].sni === 'sni.example.com');
test('名称带前缀', gen[0].name.startsWith('CF-'));

// 测试 Base64 订阅展开
const subB64 = b64Encode([sampleVmess, sampleVless].join('\n'));
const expanded = parseNodeLinks(subB64);
test('Base64 订阅自动展开为 2 节点', expanded.length === 2);

// 测试各格式输出
const raw = processAndRender({ nodeLinks, preferredIps, target: 'raw' });
test('raw 输出非空且为 base64 风格', raw.text.length > 20 && /^[A-Za-z0-9\-_]+$/.test(raw.text));

const clash = processAndRender({ nodeLinks, preferredIps, target: 'clash' });
test('clash 包含 proxies 字段', clash.text.includes('proxies:') && clash.text.includes('proxy-groups:'));
test('clash 节点数量正确', (clash.text.match(/^\s+\-\s+name:\s/gm) || []).length === 6);

const surge = processAndRender({ nodeLinks, preferredIps, target: 'surge' });
test('surge 包含 [Proxy]', surge.text.includes('[Proxy]') && surge.text.includes('FINAL,Proxy'));
// surge 目前只支持 vmess / trojan
const surgeProxyCount = (surge.text.match(/^[^\[\n].*=\s*vmess,|^[^\[\n].*=\s*trojan,/gm) || []).length;
test('surge 代理数量 = 4', surgeProxyCount === 4);

// 测试 keepOriginalHost=false
const genNoHost = generateNodes(nodeLinks, preferredIps, { keepOriginalHost: false });
test('keepOriginalHost=false 清空 SNI', genNoHost[0].sni === '' && genNoHost[0].host === '');

console.log('\n===== 输出片段预览 =====');
console.log('Clash 前 6 行:\n', clash.text.split('\n').slice(0, 6).join('\n'));
console.log('\nSurge 前 6 行:\n', surge.text.split('\n').slice(0, 6).join('\n'));

console.log('\nSmoke test done.');
