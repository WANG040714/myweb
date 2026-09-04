// Cloudflare Pages _worker.js —— WQQ 网站访问记录 + 安全防护 + 留言板 API + 设备识别
// 功能：
// 1. 安全防护：拦截漏洞路径扫描（wp-includes/xmlrpc.php 等）和已知恶意爬虫
// 2. 每次访问记录真实 IP + 时间 + 页面 + 浏览器 + 城市/运营商 + 设备型号到 KV
// 3. 统计页 /__stats?key=xxx（含设备分布可视化）
// 4. 留言板 API：GET/POST /api/guestbook（KV 存储，带 IP 限流）
// 5. 访问统计 API：GET /api/stats
// 城市定位使用 ip-api.com 免费接口（45 次/分钟限速），结果按 IP 缓存 30 天。

// ---------- 安全防护：恶意路径 / 爬虫黑名单 ----------
const MALICIOUS_PATHS = [
  '/wp-admin', '/wp-login', '/wp-includes', '/xmlrpc.php', '/wlwmanifest.xml',
  '/.env', '/.git/', '/config.php', '/phpinfo.php', '/admin.php', '/shell',
  '/cgi-bin/', '/.aws/', '/.ssh/', '/web.config', '/server-status', '/actuator'
];
// 已知恶意扫描器/攻击源 UA 关键词（不拦截 Googlebot 等正规爬虫）
const MALICIOUS_UA = [
  '1337', 'driftnet', 'internetmeasurement', 'masscan', 'nmap', 'zgrab',
  'sqlmap', 'nikto', 'acunetix', 'nessus', 'fimap', 'wpscan', 'joomscan',
  'python-requests', 'python-urllib', 'curl/', 'wget', 'libwww', 'scrapy',
  'go-http-client', 'http-client', 'okhttp', 'apache-httpclient', 'maven'
];
// 正规爬虫（放行，但标记为 bot 不计入真实访客）
const KNOWN_BOTS = [
  'googlebot', 'bingbot', 'baiduspider', 'sogou', '360spider', 'yandex',
  'duckduckbot', 'facebookexternalhit', 'twitterbot', 'slurp', 'bytespider',
  'claudebot', 'gptbot', 'chatgpt', 'anthropic', 'semrush', 'ahrefs',
  'petalbot', 'applebot', 'linkedinbot', 'pinterest'
];

// ---------- 机型代码 → 商业名称映射表（Android UA 报的是内部型号代码） ----------
const MODEL_NAMES = {
  // ===== vivo X 系列 =====
  'V2241HA': 'vivo X90s', 'V2241A': 'vivo X90', 'V2183A': 'vivo X80',
  'V2145A': 'vivo X70 Pro', 'V2118A': 'vivo X70', 'V2134A': 'vivo X70 Pro+',
  'V2056A': 'vivo X60 Pro', 'V2046A': 'vivo X60', 'V2049A': 'vivo X60s',
  'V1938A': 'vivo X30 Pro', 'V1932A': 'vivo X30', 'V1914A': 'vivo X27 Pro',
  'V1829A': 'vivo X27', 'V1809A': 'vivo X23', 'V1818A': 'vivo X21s',
  // ===== vivo S 系列 =====
  'V2309A': 'vivo S18 Pro', 'V2283A': 'vivo S17 Pro', 'V2254A': 'vivo S16',
  'V2203A': 'vivo S16 Pro', 'V2207A': 'vivo S15 Pro', 'V2199A': 'vivo S15',
  'V2185A': 'vivo S12 Pro', 'V2163A': 'vivo S12', 'V2130A': 'vivo S10 Pro',
  'V2121A': 'vivo S10', 'V2009A': 'vivo S6', 'V1930A': 'vivo S5',
  // ===== vivo Y 系列 =====
  'V2232A': 'vivo Y100', 'V2229A': 'vivo Y77', 'V2206A': 'vivo Y76s',
  'V2111A': 'vivo Y71t', 'V2106A': 'vivo Y72', 'V2100A': 'vivo Y53s',
  'V2066A': 'vivo Y30', 'V2043A': 'vivo Y31s', 'V1928A': 'vivo Y7s',
  // ===== iQOO =====
  'V2243A': 'iQOO 11', 'V2217A': 'iQOO Neo7', 'V2180A': 'iQOO 10',
  'V2178A': 'iQOO 9 Pro', 'V2171A': 'iQOO 9', 'V2141A': 'iQOO 8',
  'V2144A': 'iQOO 8 Pro', 'V2116A': 'iQOO Neo5', 'V2054A': 'iQOO 7',
  'V2011A': 'iQOO 3',
  // ===== OPPO Find =====
  'PHZ110': 'OPPO Find X7 Ultra', 'PHY110': 'OPPO Find X7', 'PHN110': 'OPPO Find X6',
  'PHW110': 'OPPO Find X6 Pro', 'PGU110': 'OPPO Find N2 Flip', 'PGW110': 'OPPO Find N2',
  'PGEM10': 'OPPO Find N3', 'PFFM20': 'OPPO Find X5', 'PFFM10': 'OPPO Find X5 Pro',
  'PEEM00': 'OPPO Find X3 Pro', 'PEHM00': 'OPPO Find X3', 'PDEM10': 'OPPO Find X2 Pro',
  'PDHM00': 'OPPO Find X2',
  // ===== OPPO Reno =====
  'PHJ110': 'OPPO Reno11', 'PHV110': 'OPPO Reno11 Pro', 'PHQ110': 'OPPO Reno9 Pro+',
  'PGY110': 'OPPO Reno8', 'PGJM10': 'OPPO Reno8 Pro+', 'PEXM00': 'OPPO Reno6 Pro',
  'PEYM00': 'OPPO Reno6', 'PDSM00': 'OPPO Reno5 Pro', 'PDNM00': 'OPPO Reno5',
  'PDPM00': 'OPPO Reno4 Pro', 'PDCM00': 'OPPO Reno4',
  // ===== 小米 =====
  'M2101K7AG': '小米 11', 'M2011K2C': '小米 11', 'M2102K1C': '小米 11 Pro',
  'M2102K1AC': '小米 11 Ultra', '2201122C': '小米 12', '2201123C': '小米 12 Pro',
  '2203121C': '小米 12S', '2206122SC': '小米 12S Ultra', '2211133C': '小米 13',
  '2210132C': '小米 13 Pro', '23127PN0CC': '小米 14', '23116PN5BC': '小米 14 Pro',
  '24031PN0DC': '小米 15', '24090PN7DC': '小米 15 Pro',
  // ===== Redmi =====
  '2107119DC': 'Redmi K40', '22021211RC': 'Redmi K50', '22122RK93C': 'Redmi K60',
  '23117RK66C': 'Redmi K70', '21091116C': 'Redmi Note 11', '22101317C': 'Redmi Note 12',
  '2312DRA50C': 'Redmi Note 13 Pro', '23049RAD8C': 'Redmi Note 12 Turbo',
  'M2006C3LC': 'Redmi 9A', '220233L2C': 'Redmi 10A', '23076RA4BC': 'Redmi Note 12 Pro',
  'M2104K10AC': 'Redmi Note 10 Pro',
  // ===== 华为 Mate =====
  'ALN-AL00': '华为 Mate 60', 'BRA-AL00': '华为 Mate 60 Pro', 'ALT-AL00': '华为 Mate 60 Pro+',
  'LIO-AL00': '华为 Mate 40 Pro', 'NOP-AN00': '华为 Mate 40 Pro+', 'TAS-AL00': '华为 Mate 30 Pro',
  'LYA-AL00': '华为 Mate 20 Pro', 'LON-AL00': '华为 Mate 20', 'NXT-AL10': '华为 Mate 9',
  // ===== 华为 P 系列 =====
  'TNY-AL00': '华为 P40', 'ELS-AN00': '华为 P40 Pro', 'ELE-AL00': '华为 P30',
  'VOG-AL00': '华为 P30 Pro', 'JAD-AL50': '华为 P50 Pro', 'ABR-AL00': '华为 P50',
  'BNE-AL00': '华为 P50 Pocket', 'BAL-AL00': '华为 nova 7', 'GLK-AL00': '华为 nova 5 Pro',
  'BRT-AL00': '华为 nova 6', 'JER-AN10': '华为 nova 8 Pro',
  // ===== 荣耀 =====
  'PGT-AN10': '荣耀 Magic5', 'PGT-AN20': '荣耀 Magic5 Pro', 'LGE-AN10': '荣耀 Magic4 Pro',
  'ELZ-AN00': '荣耀 Magic4', 'VER-AN10': '荣耀 Magic V2', 'REA-AN00': '荣耀 90',
  'REP-AN00': '荣耀 90 Pro', 'VNE-AN00': '荣耀 80', 'ANB-AN00': '荣耀 80 Pro',
  'SDY-AN00': '荣耀 70', 'HPB-AN00': '荣耀 70 Pro', 'LSA-AN00': '荣耀 60',
  'NTH-AN00': '荣耀 50', 'ALI-AN00': '荣耀 X50', 'RKY-AN00': '荣耀 X40',
  // ===== 三星 Galaxy =====
  'SM-S928B': '三星 Galaxy S24 Ultra', 'SM-S921B': '三星 Galaxy S24', 'SM-S926B': '三星 Galaxy S24+',
  'SM-S931B': '三星 Galaxy S25', 'SM-S938B': '三星 Galaxy S25 Ultra', 'SM-S936B': '三星 Galaxy S25+',
  'SM-S918B': '三星 Galaxy S23 Ultra', 'SM-S911B': '三星 Galaxy S23', 'SM-S916B': '三星 Galaxy S23+',
  'SM-S901B': '三星 Galaxy S22', 'SM-S908B': '三星 Galaxy S22 Ultra',
  'SM-G991B': '三星 Galaxy S21', 'SM-G998B': '三星 Galaxy S21 Ultra',
  'SM-A556B': '三星 Galaxy A55', 'SM-A546B': '三星 Galaxy A54', 'SM-A536B': '三星 Galaxy A53',
  'SM-A525F': '三星 Galaxy A52', 'SM-A145R': '三星 Galaxy A14',
  'SM-F946B': '三星 Galaxy Z Fold5', 'SM-F936B': '三星 Galaxy Z Fold4',
  'SM-F731B': '三星 Galaxy Z Flip5', 'SM-F721B': '三星 Galaxy Z Flip4',
  'SM-N986B': '三星 Galaxy Note20 Ultra', 'SM-N975F': '三星 Galaxy Note10+',
  // ===== OnePlus =====
  'PHK110': '一加 11', 'PHB110': '一加 11 Pro', 'PJZ110': '一加 12',
  'PGZ110': '一加 Ace2', 'PJA110': '一加 Ace3', 'PJX110': '一加 Ace3 Pro',
  // ===== 魅族 =====
  'M971Q': '魅族 21', 'M461Q': '魅族 20', 'M381Q': '魅族 20 Pro'
};

// 通用型号代码模式 → 品牌反推（UA 不标品牌时的兜底）
const CODE_TO_BRAND = [
  [/^V\d{4}/, 'vivo'], [/^v\d{4}/, 'vivo'], [/^i?QOO/i, 'iQOO'],
  [/^CPH\d{4}/, 'OPPO'], [/^P[A-Z]{2}M\d/, 'OPPO'], [/^PH[A-Z]\d{3}/, 'OPPO'],
  [/^M\d{7}/, '小米'], [/^22\d{5}/, '小米'], [/^23\d{5}/, '小米'],
  [/^SM-[A-Z0-9]+/, '三星'], [/^GT-\d+/, '三星'],
  [/^ELS|^VOG|^TNY|^ELE/, '华为'],
  [/^PGT|^LGE|^REA|^VNE|^SDY|^LSA|^NTH|^ALI|^RKY|^ANB|^HPB|^VER|^ELZ|^REP/, '荣耀'],
  [/^[A-Z]{3}-[A-Z0-9]{2,4}/, '华为']
];

// ---------- 设备识别（精简版 ua-parser-js 思路） ----------
function detectDevice(ua) {
  if (!ua || ua === '-') return { type: '未知', brand: '未知', model: '未知', os: '未知', browser: '未知' };
  const u = ua.toLowerCase();
  const d = { type: '桌面', brand: '', model: '', os: '', browser: '' };

  // --- 设备类型 ---
  if (/mobile|iphone|android.*mobile|miui browser|huawei.*browser/i.test(u)) d.type = '手机';
  else if (/ipad|tablet|kindle|silk|playbook|nexus 7|nexus 10/i.test(u)) d.type = '平板';
  else if (/bot|spider|crawl|slurp|scan|monitor|headless|curl|wget|python|java|node|measurement|validus|domains-distillery/i.test(u)) d.type = '机器人';
  else d.type = '桌面';

  // --- 品牌 ---
  if (/iphone|ipad|ipod|mac os|macintosh/i.test(u)) d.brand = 'Apple';
  else if (/honor|hihonor|荣耀/i.test(u)) d.brand = '荣耀';
  else if (/huawei|harmonyos|emui/i.test(u)) d.brand = 'Huawei';
  else if (/xiaomi|miui|redmi|poco|mi-|mix\d|mi \d/i.test(u)) d.brand = 'Xiaomi';
  else if (/oppo|realme|coloros|cp[h-z]\d{4}|peem\d|p[a-z]{2}m\d/i.test(u)) d.brand = 'OPPO';
  else if (/vivo|funtouch|originos|v\d{4}|v2\d{3}|iQOO/i.test(u)) d.brand = 'vivo';
  else if (/samsung|sm-[a-z0-9]+/i.test(u)) d.brand = 'Samsung';
  else if (/pixel|google/i.test(u)) d.brand = 'Google';
  else if (/oneplus/i.test(u)) d.brand = 'OnePlus';
  else if (/meizu/i.test(u)) d.brand = '魅族';
  else if (/windows phone|windows nt|windows/i.test(u)) d.brand = 'Microsoft';
  else if (/linux/i.test(u) && !/android/i.test(u)) d.brand = 'Linux';
  else if (d.type === '机器人') d.brand = '爬虫';
  else d.brand = '未知';

  // --- 型号（优先精确匹配） ---
  let m;
  // iPhone 系列（iOS 版本 → 机型，iOS 18=iPhone16 系列，iOS 19=iPhone17 系列(2025跳版)）
  if ((m = ua.match(/iPhone\s*;\s*CPU\s*iPhone\s*OS\s*([\d_]+)/i))) {
    const v = m[1].replace(/_/g, '.');
    const vn = parseFloat(v);
    const models = [
      [30, '未来 iPhone 系列'], [26, 'iPhone 17 系列'], [19, 'iPhone 17 系列'],
      [18, 'iPhone 16 系列'], [17, 'iPhone 15 系列'], [16, 'iPhone 14 系列'],
      [15, 'iPhone 13 系列'], [14, 'iPhone 12 系列'], [13, 'iPhone 11 系列'],
      [12, 'iPhone XS/XR 系列'], [11, 'iPhone X 系列'], [10, 'iPhone 7/8 系列'], [9, 'iPhone 6s 系列']
    ];
    d.model = 'iPhone';
    for (const [ver, name] of models) { if (vn >= ver) { d.model = name; break; } }
    d.os = 'iOS ' + v;
  }
  // iPad
  else if ((m = ua.match(/iPad.*?OS\s*([\d_]+)/i))) {
    d.model = 'iPad';
    d.os = 'iPadOS ' + m[1].replace(/_/g, '.');
  }
  // Android 具体型号（标准 "Android X; 型号 Build/" 或旧式 "Android X; U; zh-cn; 型号 Build/"）
  else if ((m = ua.match(/\(Linux; (?:U; )?Android\s*([\d.]+);\s*(?:zh-cn[;,]?\s*)?([^;)]+?)\s*Build\//i))) {
    d.os = 'Android ' + m[1];
    let mod = m[2].trim();
    const brandLower = d.brand.toLowerCase();
    // 去掉品牌前缀重复：如 "Xiaomi M2101K7AG" / "HUAWEI VOG-L29"
    const brandPrefixes = [d.brand, 'Xiaomi', 'Redmi', 'Huawei', 'HONOR', 'OPPO', 'vivo', 'Samsung', 'Google', 'OnePlus', 'realme', 'POCO'];
    for (const bp of brandPrefixes) {
      if (mod.toLowerCase().startsWith(bp.toLowerCase())) { mod = mod.slice(bp.length).trim(); break; }
    }
    // 某些机型品牌未命中时，根据型号代码反推品牌
    if (d.brand === '未知') {
      for (const [re, br] of CODE_TO_BRAND) {
        if (re.test(mod)) { d.brand = br; break; }
      }
    }
    // 查映射表：型号代码 → 商业名称（如 V2241HA → vivo X90s）
    const code = mod.toUpperCase();
    if (MODEL_NAMES[code]) {
      d.model = MODEL_NAMES[code];
    } else {
      d.model = mod || (d.brand !== '未知' ? d.brand : 'Android 设备');
      if (d.brand !== '未知') d.model = d.brand + ' ' + d.model;
    }
  }
  // Windows
  else if ((m = ua.match(/Windows NT\s*([\d.]+)/i))) {
    const winVer = { '10.0': 'Windows 10/11', '6.3': 'Windows 8.1', '6.2': 'Windows 8', '6.1': 'Windows 7', '6.0': 'Windows Vista', '5.1': 'Windows XP' };
    d.model = winVer[m[1]] || 'Windows';
    d.os = d.model;
  }
  // macOS
  else if ((m = ua.match(/Mac OS X\s*([\d_.]+)/i))) {
    d.os = 'macOS ' + m[1].replace(/_/g, '.');
    d.model = 'Mac';
  }
  // Linux / 其他
  else if (/Android/i.test(u)) {
    d.os = 'Android';
    d.model = d.brand !== '未知' ? d.brand : 'Android 设备';
  }
  else if (/Linux/i.test(u)) { d.os = 'Linux'; d.model = 'Linux 设备'; }
  else if (/Windows Phone/i.test(u)) { d.os = 'Windows Phone'; d.model = 'Windows Phone'; }
  else if (d.type === '机器人') { d.model = '爬虫程序'; }

  // --- 浏览器 ---
  if (/micromessenger|wechat|wxwork/i.test(u)) d.browser = '微信';
  else if (/qqbrowser|mqqbrowser/i.test(u)) d.browser = 'QQ浏览器';
  else if (/ucbrowser/i.test(u)) d.browser = 'UC浏览器';
  else if (/edg(e|a|ios)?\//i.test(u)) d.browser = 'Edge';
  else if (/firefox|fxios/i.test(u)) d.browser = 'Firefox';
  else if (/opr\/|opera/i.test(u)) d.browser = 'Opera';
  else if (/samsungbrowser/i.test(u)) d.browser = 'Samsung Internet';
  else if (/chrome|crios/i.test(u)) d.browser = 'Chrome';
  else if (/safari/i.test(u)) d.browser = 'Safari';
  else if (/bot|spider|crawl|measurement|validus/i.test(u)) d.browser = '爬虫';
  else if (/node/i.test(u)) d.browser = 'Node.js';
  else d.browser = '未知';

  return d;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const STATS_KEY = env.STATS_KEY || 'wqq2026';
    const ua = request.headers.get('User-Agent') || '';

    // ========== 安全防护层 ==========
    const pathLower = url.pathname.toLowerCase();
    // 拦截漏洞路径扫描（直接 403，不记录）
    if (MALICIOUS_PATHS.some(p => pathLower.startsWith(p))) {
      return new Response('403 Forbidden', { status: 403 });
    }
    // 拦截已知恶意扫描器 UA
    if (MALICIOUS_UA.some(k => ua.toLowerCase().includes(k))) {
      return new Response('403 Forbidden', { status: 403 });
    }

    // 统计页：/__stats?key=xxx
    if (url.pathname === '/__stats') {
      if (url.searchParams.get('key') !== STATS_KEY) {
        return new Response('403 Forbidden', { status: 403 });
      }
      return handleStats(env, request);
    }

    // 留言板 API
    if (url.pathname === '/api/guestbook') {
      if (request.method === 'POST') return handleGuestbookPost(request, env);
      if (request.method === 'GET') return handleGuestbookGet(env);
      return new Response('Method Not Allowed', { status: 405 });
    }

    // 访问统计 API（页面页脚展示用）
    if (url.pathname === '/api/stats') {
      return handleStatsApi(env);
    }

    // [DEBUG] KV 分页诊断端点（仅带正确 key 时返回，用于排查统计读取）
    if (url.pathname === '/api/diag' && url.searchParams.get('key') === STATS_KEY) {
      return handleDiag(env);
    }

    // R2 图片代理：/r2/xxx.webp → 从 R2 bucket 读取（图片已存 R2 store/img/）
    if (url.pathname.startsWith('/r2/') && env.STORE) {
      try {
        const key = url.pathname.slice(4); // 去掉 /r2/
        const obj = await env.STORE.get(key);
        if (!obj) return new Response('Not Found', { status: 404 });
        const headers = new Headers();
        obj.writeHttpMetadata(headers);
        headers.set('etag', obj.httpEtag);
        headers.set('Cache-Control', 'public, max-age=31536000, immutable');
        return new Response(obj.body, { headers });
      } catch (e) {
        return new Response('R2 Error: ' + e.message, { status: 500 });
      }
    }

    // 记录访问（waitUntil 保证写入在响应后完成；只记录文档请求，跳过静态资源和 API）
    const isAsset = /\.(css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|map|txt)$/i.test(url.pathname);
    if (!isAsset && !url.pathname.startsWith('/api/') && request.method === 'GET') {
      ctx.waitUntil(recordVisit(request, env, url).catch(() => {}));
    }

    // 正常返回静态页面
    return env.ASSETS.fetch(request);
  },
};

// ---------- 访问记录 ----------

// 查询 IP 城市信息（带 KV 缓存，避免每次访问都打第三方接口）
async function getGeo(env, ip) {
  if (!ip || ip === '-') return null;
  try {
    const cached = await env.VISITS.get('geo:' + ip);
    if (cached) return JSON.parse(cached);
  } catch (e) {}
  try {
    const resp = await fetch(
      'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,country,regionName,city,isp,query&lang=zh-CN',
      { headers: { 'User-Agent': 'wqq-site' } }
    );
    const data = await resp.json();
    if (data && data.status === 'success') {
      const geo = { city: data.city || null, region: data.regionName || null, isp: data.isp || null };
      // 缓存 30 天
      await env.VISITS.put('geo:' + ip, JSON.stringify(geo), { expirationTtl: 2592000 }).catch(() => {});
      return geo;
    }
  } catch (e) {}
  return null;
}

async function recordVisit(request, env, url) {
  const ip = request.headers.get('CF-Connecting-IP') || '-';
  const country = request.headers.get('CF-IPCountry') || '-';
  const ua = (request.headers.get('User-Agent') || '-').slice(0, 300);
  const path = url.pathname;
  const t = Date.now();
  const geo = await getGeo(env, ip);
  const device = detectDevice(ua);
  // key 唯一：时间戳 + IP + 随机串
  const key = `v:${t}:${ip}:${Math.random().toString(36).slice(2, 8)}`;
  await env.VISITS.put(
    key,
    JSON.stringify({
      ip,
      country,
      city: geo ? geo.city : null,
      region: geo ? geo.region : null,
      isp: geo ? geo.isp : null,
      path,
      ua,
      t,
      dev: device, // { type, brand, model, os, browser }
    })
  );
}

// ---------- 留言板 ----------

// 读取最近 100 条留言（倒序）
async function handleGuestbookGet(env) {
  const msgs = [];
  try {
    const list = await env.VISITS.list({ prefix: 'g:', limit: 200 });
    for (const k of list.keys) {
      const v = await env.VISITS.get(k.name);
      if (v) msgs.push(JSON.parse(v));
    }
  } catch (e) {
    return json({ ok: false, error: '读取留言失败' }, 500);
  }
  msgs.sort((a, b) => b.t - a.t);
  return json({ ok: true, messages: msgs.slice(0, 100) });
}

// 提交留言（带简单限流：每 IP 每 60 秒最多 1 条）
async function handleGuestbookPost(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, error: '请求格式错误' }, 400);
  }

  const name = String(body.name || '').trim().slice(0, 20);
  const text = String(body.text || '').trim().slice(0, 300);

  if (!name) return json({ ok: false, error: '请填写昵称' }, 400);
  if (!text) return json({ ok: false, error: '请填写留言内容' }, 400);

  // IP 限流：60 秒内同 IP 最多 1 条
  const rateKey = 'rl:' + ip;
  const last = await env.VISITS.get(rateKey);
  const now = Date.now();
  if (last && now - parseInt(last, 10) < 60000) {
    const waitSec = Math.ceil((60000 - (now - parseInt(last, 10))) / 1000);
    return json({ ok: false, error: `操作太频繁，请 ${waitSec} 秒后再试` }, 429);
  }
  await env.VISITS.put(rateKey, String(now), { expirationTtl: 120 });

  const key = `g:${now}:${ip}:${Math.random().toString(36).slice(2, 8)}`;
  await env.VISITS.put(key, JSON.stringify({ name, text, t: now, ip }));
  return json({ ok: true, message: '留言成功' });
}

// ---------- 访问统计 API ----------

// [DEBUG] KV 分页+取值诊断：逐页输出 list() 行为 + 值读取成功率，定位统计读取差异
async function handleDiag(env) {
  const out = { pages: [], totalKeys: 0, maxTs: 0, maxTsTime: null };
  try {
    let cursor;
    let pageNo = 0;
    for (;;) {
      const opts = { prefix: 'v:', limit: 1000 };
      if (cursor) opts.cursor = cursor;
      const list = await env.VISITS.list(opts);
      const names = (list.keys || []).map(k => k.name);
      let pageMaxTs = 0;
      for (const n of names) {
        const ts = parseInt((n.split(':')[1] || '0'), 10);
        if (ts > pageMaxTs) pageMaxTs = ts;
        if (ts > out.maxTs) out.maxTs = ts;
      }
      out.pages.push({
        page: pageNo,
        keys: names.length,
        list_complete: !!list.list_complete,
        has_cursor: !!list.cursor,
        cursor_prefix: list.cursor ? String(list.cursor).slice(0, 12) : null,
        pageMaxTs,
        pageMaxTime: pageMaxTs ? new Date(pageMaxTs).toISOString() : null,
      });
      out.totalKeys += names.length;
      if (!list.list_complete && list.cursor) { cursor = list.cursor; pageNo++; continue; }
      break;
    }
    out.maxTsTime = out.maxTs ? new Date(out.maxTs).toISOString() : null;

    // 值读取诊断：模拟 handleStats 的 readVisitValues，统计成功/失败
    const keys = await listAllVisitKeys(env);
    out.diagKeysAll = keys.length;
    let okValues = 0, nullFailed = 0, parseOk = 0, parseFail = 0;
    const nullKeys = [];
    // 分批读取（与 readVisitValues 一致，chunk=200）
    for (let i = 0; i < keys.length; i += 200) {
      const slice = keys.slice(i, i + 200);
      const vals = await Promise.all(slice.map(k => env.VISITS.get(k).catch(() => null)));
      for (let j = 0; j < slice.length; j++) {
        const v = vals[j];
        if (v == null) { nullFailed++; if (nullKeys.length < 20) nullKeys.push(slice[j]); }
        else {
          okValues++;
          try { JSON.parse(v); parseOk++; } catch (e) { parseFail++; }
        }
      }
    }
    out.read = {
      keysAll: keys.length,
      valuesOk: okValues,
      valuesNullFailed: nullFailed,
      jsonParseOk: parseOk,
      jsonParseFail: parseFail,
      sampleNullKeys: nullKeys,
    };

    return json({ ok: true, ...out });
  } catch (e) {
    return json({ ok: false, error: String(e && e.message || e), ...out }, 500);
  }
}

// 游标分页遍历所有 v: 前缀键（避免 limit 截断导致新记录读不到）
async function listAllVisitKeys(env, pageSize = 1000) {
  const keys = [];
  let cursor;
  let guard = 0;
  for (;;) {
    const opts = { prefix: 'v:', limit: pageSize };
    if (cursor) opts.cursor = cursor;
    const list = await env.VISITS.list(opts);
    // 防御：没返回键则停止
    if (!list.keys || list.keys.length === 0) break;
    for (const k of list.keys) keys.push(k.name);
    // 无游标则分页结束；游标未推进则终止防死循环
    if (!list.cursor) break;
    if (list.cursor === cursor) break;
    cursor = list.cursor;
    if (++guard > 50) break; // 极端防御
  }
  return keys;
}

// 分批并行读取 KV 值，避免单次并发过多触发 Workers 限制
async function readVisitValues(env, keys, chunk = 200) {
  const values = [];
  for (let i = 0; i < keys.length; i += chunk) {
    const slice = keys.slice(i, i + chunk);
    const vals = await Promise.all(slice.map(k => env.VISITS.get(k).catch(() => null)));
    for (const v of vals) values.push(v);
  }
  return values;
}

async function handleStatsApi(env) {
  try {
    const keys = await listAllVisitKeys(env);
    const ips = new Set();
    let total = 0;
    // 分批并行读取，避免串行等待
    const values = await readVisitValues(env, keys);
    for (const v of values) {
      if (v) {
        total++;
        try { ips.add(JSON.parse(v).ip); } catch (e) {}
      }
    }
    return json({ ok: true, total, uniqIps: ips.size });
  } catch (e) {
    return json({ ok: false, error: '统计失败' }, 500);
  }
}

// ---------- 统计页 ----------

async function handleStats(env, request) {
  // 用 Cache API 缓存统计页 60 秒，避免每次请求都全量读 KV（大幅提速）
  const cache = caches.default;
  const cacheKey = new Request(request.url, { method: 'GET' });
  try {
    const cached = await cache.match(cacheKey);
    if (cached) return cached;
  } catch (e) { /* 缓存不可用则继续实时计算 */ }

  // 只读取 v: 前缀的访问记录（跳过 geo/g/rl 键），并行 get 大幅提速
  const rows = [];
  try {
    const keys = await listAllVisitKeys(env);
    const values = await readVisitValues(env, keys);
    for (const v of values) {
      if (v) { try { rows.push(JSON.parse(v)); } catch (e) {} }
    }
  } catch (e) {
    return new Response('统计读取失败：' + e.message, { status: 500 });
  }
  rows.sort((a, b) => b.t - a.t);

  // 汇总统计
  const uniqIps = new Set(rows.map((r) => r.ip));
  const byDay = {};
  const byPath = {};
  const byCountry = {};
  const byCity = {};
  // 设备统计
  const byDevType = {};
  const byBrand = {};
  const byModel = {};
  const byOs = {};
  const byBrowser = {};
  for (const r of rows) {
    const d = new Date(r.t).toISOString().slice(0, 10);
    byDay[d] = (byDay[d] || 0) + 1;
    byPath[r.path] = (byPath[r.path] || 0) + 1;
    byCountry[r.country] = (byCountry[r.country] || 0) + 1;
    const city = r.city || (r.country === 'CN' ? '中国(未知城市)' : r.country);
    byCity[city] = (byCity[city] || 0) + 1;
    // 设备维度（旧数据没有 dev 字段时用 UA 现场解析）
    const dev = r.dev || detectDevice(r.ua || '');
    byDevType[dev.type] = (byDevType[dev.type] || 0) + 1;
    byBrand[dev.brand] = (byBrand[dev.brand] || 0) + 1;
    byModel[dev.model] = (byModel[dev.model] || 0) + 1;
    byOs[dev.os] = (byOs[dev.os] || 0) + 1;
    byBrowser[dev.browser] = (byBrowser[dev.browser] || 0) + 1;
  }

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const fmtLoc = (r) => {
    const parts = [];
    if (r.city) parts.push(r.city);
    if (r.region && r.region !== r.city) parts.push(r.region);
    if (r.country && r.country !== '-') parts.push(r.country);
    const main = parts.length ? esc(parts.join('，')) : esc(r.country || '-');
    const sub = r.isp ? `<div class="isp">${esc(r.isp)}</div>` : '';
    return main + sub;
  };

  // 把 {key: count} 转成标签块
  const kvItems = (obj, limit) =>
    Object.entries(obj)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([k, c]) => `<span class="item">${esc(k)}<b>${c}</b></span>`)
      .join('');
  const dayItems = (o) => kvItems(o, 10);
  const pathItems = (o) => kvItems(o, 8);
  const countryItems = (o) => kvItems(o, 8);
  const cityItems = (o) => kvItems(o, 10);

  const trs = rows
    .slice(0, 300)
    .map(
      (r) => {
        const dev = r.dev || detectDevice(r.ua || '');
        const devStr = dev.type === '机器人' ? '🤖 ' + dev.model
          : (dev.brand !== '未知' ? dev.brand + ' ' : '') + (dev.model !== '未知' ? dev.model : '') + (dev.os && dev.os !== '未知' ? ' · ' + dev.os : '');
        return `<tr><td class="ip">${esc(r.ip)}</td><td class="time">${new Date(r.t).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</td><td class="path">${esc(r.path)}</td><td class="loc">${fmtLoc(r)}</td><td class="dev">${esc(devStr)}</td><td class="ua" title="${esc(r.ua)}">${esc(r.ua)}</td></tr>`;
      }
    )
    .join('');

  // 设备分布面板（带进度条的可视化）
  const devPanel = (obj, total, limit) => {
    const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, limit);
    if (!entries.length) return '<span style="color:#8aa3ba;font-size:12px">暂无</span>';
    const max = entries[0][1];
    return entries.map(([k, c]) => {
      const pct = Math.round((c / max) * 100);
      const share = Math.round((c / total) * 100);
      return `<div class="bar-row"><div class="bar-lbl"><span>${esc(k)}</span><span class="bar-num">${c} <em>${share}%</em></span></div><div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div></div>`;
    }).join('');
  };

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WQQ 网站访问统计</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "PingFang SC", "Microsoft YaHei", "Helvetica Neue", sans-serif;
    margin: 0; padding: 0;
    background: linear-gradient(165deg, #eaf2fb 0%, #dcebf8 45%, #cfe3f4 100%);
    min-height: 100vh;
    color: #1d2d3d;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 32px 18px 60px; }
  header { text-align: center; margin-bottom: 26px; }
  h1 {
    font-size: 28px; font-weight: 800; margin: 0 0 6px; letter-spacing: -0.5px;
    background: linear-gradient(120deg, #2f6fa8, #4a90d9 55%, #7ab8ec);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .sub { font-size: 13px; color: #5a7a99; }

  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 22px 0; }
  .card {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px; padding: 20px 22px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
  }
  .card .num { font-size: 34px; font-weight: 800; color: #2f6fa8; letter-spacing: -1px; }
  .card .lbl { font-size: 13px; color: #5a7a99; margin-top: 6px; }

  .cols { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin: 16px 0 26px; }
  .panel {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px; padding: 18px 20px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
  }
  .panel h2 { font-size: 15px; font-weight: 700; margin: 0 0 12px; color: #1d2d3d; }
  .kv { display: flex; flex-wrap: wrap; gap: 6px; }
  .kv .item {
    font-size: 12px; line-height: 1;
    background: #e8f1fa; color: #3a5a78;
    border-radius: 8px; padding: 8px 10px;
  }
  .kv .item b { color: #2f6fa8; font-weight: 700; margin-left: 4px; }

  /* 设备可视化 */
  .dev-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 16px 0 26px; }
  .dev-panel {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px; padding: 18px 20px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
  }
  .dev-panel h2 { font-size: 15px; font-weight: 700; margin: 0 0 14px; color: #1d2d3d; }
  .bar-row { margin-bottom: 11px; }
  .bar-lbl {
    display: flex; justify-content: space-between; align-items: baseline;
    font-size: 12.5px; color: #3a5a78; margin-bottom: 4px;
  }
  .bar-lbl .bar-num { font-weight: 700; color: #2f6fa8; }
  .bar-lbl .bar-num em { font-style: normal; font-size: 11px; color: #8aa3ba; font-weight: 500; margin-left: 3px; }
  .bar-track {
    height: 7px; background: #e4edf6; border-radius: 4px; overflow: hidden;
  }
  .bar-fill {
    height: 100%; border-radius: 4px;
    background: linear-gradient(90deg, #7ab8ec, #4a90d9);
    transition: width 0.8s ease;
  }

  .table-title { font-size: 17px; font-weight: 700; margin: 0 0 12px; color: #1d2d3d; }
  .table-wrap {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
    overflow: hidden;
  }
  .table-scroll { overflow-x: auto; max-height: 62vh; overflow-y: auto; }
  table {
    width: 100%; border-collapse: collapse; table-layout: fixed;
    font-size: 12px; min-width: 820px;
  }
  col.ip { width: 13%; }
  col.time { width: 15%; }
  col.path { width: 10%; }
  col.loc { width: 15%; }
  col.dev { width: 19%; }
  col.ua { width: 28%; }
  thead th {
    position: sticky; top: 0; z-index: 2;
    background: #f2f7fc;
    color: #33506e; font-weight: 700;
    text-align: left; padding: 11px 12px;
    border-bottom: 1px solid #dce8f3;
    font-size: 12px; white-space: nowrap;
  }
  tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #eef3f8;
    vertical-align: middle;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  td.ip { font-family: "SF Mono", Consolas, Menlo, monospace; font-size: 11.5px; color: #3a5a78; }
  td.time { color: #5a7a99; font-variant-numeric: tabular-nums; }
  td.path { color: #2f6fa8; font-weight: 600; }
  td.loc { color: #33475b; }
  td.loc .isp { color: #8aa3ba; font-size: 11px; margin-top: 2px; }
  td.dev { color: #33506e; font-weight: 500; }
  td.ua { color: #6b8299; cursor: help; }
  tbody tr:hover td { background: #eaf3fc; }
  tbody tr:last-child td { border-bottom: none; }
  .empty { text-align: center; color: #8aa3ba; padding: 40px 0 !important; white-space: normal !important; }

  @media (max-width: 820px) {
    .cards { grid-template-columns: 1fr; }
    .cols { grid-template-columns: 1fr; }
    .dev-grid { grid-template-columns: 1fr; }
    h1 { font-size: 23px; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>📊 WQQ 网站访问统计</h1>
    <div class="sub">数据实时记录 · 含安全防护与设备识别</div>
  </header>
  <div class="cards">
    <div class="card"><div class="num">${rows.length}</div><div class="lbl">记录总数（近 1000 条）</div></div>
    <div class="card"><div class="num">${uniqIps.size}</div><div class="lbl">独立 IP</div></div>
    <div class="card"><div class="num">${Object.keys(byDay).length > 0 ? Object.values(byDay).reduce((a, b) => a + b, 0) : 0}</div><div class="lbl">总访问次数</div></div>
  </div>
  <div class="dev-grid">
    <div class="dev-panel"><h2>📱 设备类型</h2>${devPanel(byDevType, rows.length, 6)}</div>
    <div class="dev-panel"><h2>🏷️ 品牌分布</h2>${devPanel(byBrand, rows.length, 8)}</div>
    <div class="dev-panel"><h2>💻 操作系统</h2>${devPanel(byOs, rows.length, 6)}</div>
    <div class="dev-panel"><h2>🔍 浏览器</h2>${devPanel(byBrowser, rows.length, 6)}</div>
    <div class="dev-panel" style="grid-column: span 2"><h2>📟 具体设备型号 TOP 10</h2>${devPanel(byModel, rows.length, 10)}</div>
  </div>
  <div class="cols">
    <div class="panel"><h2>📅 按天</h2><div class="kv">${dayItems(byDay) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>🧭 访问页面</h2><div class="kv">${pathItems(byPath) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>🌍 国家/地区</h2><div class="kv">${countryItems(byCountry) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>📍 城市 TOP</h2><div class="kv">${cityItems(byCity) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
  </div>
  <div class="table-title">🕒 最近访问明细（最新 300 条 · 设备型号列）</div>
  <div class="table-wrap">
    <div class="table-scroll">
      <table>
        <colgroup>
          <col class="ip"><col class="time"><col class="path"><col class="loc"><col class="dev"><col class="ua">
        </colgroup>
        <thead><tr><th>IP</th><th>时间（北京时间）</th><th>页面</th><th>位置 / 运营商</th><th>设备型号</th><th>User-Agent（悬停查看完整）</th></tr></thead>
        <tbody>${trs || '<tr><td class="empty" colspan="6">还没有记录</td></tr>'}</tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>`;

  const resp = new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=300', // Cloudflare 边缘缓存 5 分钟
    },
  });
  // 写入 Cache API（5 分钟内同一 URL 直接命中缓存，首次加载也接近静态速度）
  try {
    await cache.put(cacheKey, resp.clone());
  } catch (e) {}
  return resp;
}

// ---------- 工具 ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
