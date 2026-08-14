// Cloudflare Pages _worker.js —— WQQ 网站访问 IP 记录器 + 留言板 API
// 功能：
// 1. 每次访问记录真实 IP + 时间 + 页面 + 浏览器 + 城市/运营商到 KV
// 2. 统计页 /__stats?key=xxx
// 3. 留言板 API：GET/POST /api/guestbook（KV 存储，带 IP 限流）
// 4. 访问统计 API：GET /api/stats
// 城市定位使用 ip-api.com 免费接口（45 次/分钟限速），结果按 IP 缓存 30 天。
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const STATS_KEY = env.STATS_KEY || 'wqq2026';

    // 统计页：/__stats?key=xxx
    if (url.pathname === '/__stats') {
      if (url.searchParams.get('key') !== STATS_KEY) {
        return new Response('403 Forbidden', { status: 403 });
      }
      return handleStats(env);
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
  const ua = (request.headers.get('User-Agent') || '-').slice(0, 200);
  const path = url.pathname;
  const t = Date.now();
  const geo = await getGeo(env, ip);
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

async function handleStatsApi(env) {
  try {
    const list = await env.VISITS.list({ prefix: 'v:', limit: 1000 });
    const ips = new Set();
    let total = 0;
    for (const k of list.keys) {
      const v = await env.VISITS.get(k.name);
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

async function handleStats(env) {
  const rows = [];
  try {
    const list = await env.VISITS.list({ limit: 1000 });
    for (const k of list.keys) {
      if (!k.name.startsWith('v:')) continue; // 跳过 geo 缓存键
      const v = await env.VISITS.get(k.name);
      if (v) rows.push(JSON.parse(v));
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
  for (const r of rows) {
    const d = new Date(r.t).toISOString().slice(0, 10);
    byDay[d] = (byDay[d] || 0) + 1;
    byPath[r.path] = (byPath[r.path] || 0) + 1;
    byCountry[r.country] = (byCountry[r.country] || 0) + 1;
    const city = r.city || (r.country === 'CN' ? '中国(未知城市)' : r.country);
    byCity[city] = (byCity[city] || 0) + 1;
  }
  const dayStr = Object.entries(byDay).map(([d, c]) => `${d}: ${c} 次`).join('<br>');
  const pathStr = Object.entries(byPath).sort((a, b) => b[1] - a[1]).map(([p, c]) => `${p} — ${c}`).join('<br>');
  const countryStr = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${c}: ${n}`).join(' / ');
  const cityStr = Object.entries(byCity).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${c}: ${n}`).join('<br>');

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const fmtLoc = (r) => {
    const parts = [];
    if (r.city) parts.push(r.city);
    if (r.region && r.region !== r.city) parts.push(r.region);
    if (r.country && r.country !== '-') parts.push(r.country);
    const main = parts.length ? esc(parts.join('，')) : esc(r.country || '-');
    const sub = r.isp ? `<div style="color:#86868b">${esc(r.isp)}</div>` : '';
    return main + sub;
  };

  const trs = rows
    .slice(0, 500)
    .map(
      (r) =>
        `<tr><td>${esc(r.ip)}</td><td>${new Date(r.t).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</td><td>${esc(r.path)}</td><td>${fmtLoc(r)}</td><td class="ua">${esc(r.ua)}</td></tr>`
    )
    .join('');

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WQQ 网站访问统计</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 0; background: #eef4fb; color: #1d1d1f; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px 60px; }
  h1 { font-size: 24px; font-weight: 600; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin: 20px 0; }
  .card { background: rgba(255,255,255,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.6); border-radius: 14px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .card .num { font-size: 30px; font-weight: 700; color: #4a90d9; }
  .card .lbl { font-size: 13px; color: #86868b; margin-top: 4px; }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; margin: 14px 0; }
  .panel { background: rgba(255,255,255,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.6); border-radius: 14px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 13px; line-height: 1.9; }
  .panel h2 { font-size: 15px; margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.6); border-radius: 14px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 12px; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #eee; white-space: nowrap; }
  th { background: rgba(250,250,250,0.6); color: #86868b; font-weight: 500; }
  td.ua { white-space: normal; max-width: 320px; color: #86868b; }
  tr:hover td { background: #f0f7ff; }
</style>
</head>
<body>
<div class="wrap">
  <h1>📊 WQQ 网站访问统计</h1>
  <div class="cards">
    <div class="card"><div class="num">${rows.length}</div><div class="lbl">记录总数（最多显示 1000 条）</div></div>
    <div class="card"><div class="num">${uniqIps.size}</div><div class="lbl">独立 IP</div></div>
    <div class="card"><div class="num">${Object.keys(byDay).length > 0 ? Object.values(byDay).reduce((a, b) => a + b, 0) : 0}</div><div class="lbl">总访问次数</div></div>
  </div>
  <div class="cols">
    <div class="panel"><h2>📅 按天</h2>${dayStr || '暂无'}</div>
    <div class="panel"><h2>🧭 访问页面</h2>${pathStr || '暂无'}</div>
    <div class="panel"><h2>🌍 国家/地区</h2>${countryStr || '暂无'}</div>
    <div class="panel"><h2>📍 城市 TOP</h2>${cityStr || '暂无'}</div>
  </div>
  <h2 style="font-size:16px">🕒 最近访问明细</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>IP</th><th>时间（北京时间）</th><th>页面</th><th>位置 / 运营商</th><th>User-Agent</th></tr></thead>
    <tbody>${trs || '<tr><td colspan="5">还没有记录</td></tr>'}</tbody>
  </table>
  </div>
</div>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ---------- 工具 ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
