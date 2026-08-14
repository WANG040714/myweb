// Cloudflare Pages _worker.js —— WQQ 网站访问 IP 记录器（含城市级定位）
// 每次访问先经过本脚本：记录真实 IP + 时间 + 页面 + 浏览器 + 城市/运营商到 KV，
// 然后正常返回静态页面。统计页位于 /__stats?key=你的密码
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

    // 记录访问（waitUntil 保证写入在响应后完成；只记录文档请求，跳过图片等静态资源）
    const isAsset = /\.(css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|map|txt)$/i.test(url.pathname);
    if (!isAsset && request.method === 'GET') {
      ctx.waitUntil(recordVisit(request, env, url).catch(() => {}));
    }

    // 正常返回静态页面
    return env.ASSETS.fetch(request);
  },
};

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
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 0; background: #f5f5f7; color: #1d1d1f; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px 60px; }
  h1 { font-size: 24px; font-weight: 600; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin: 20px 0; }
  .card { background: #fff; border-radius: 14px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .card .num { font-size: 30px; font-weight: 700; color: #ff6700; }
  .card .lbl { font-size: 13px; color: #86868b; margin-top: 4px; }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; margin: 14px 0; }
  .panel { background: #fff; border-radius: 14px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 13px; line-height: 1.9; }
  .panel h2 { font-size: 15px; margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 14px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 12px; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #eee; white-space: nowrap; }
  th { background: #fafafa; color: #86868b; font-weight: 500; }
  td.ua { white-space: normal; max-width: 320px; color: #86868b; }
  tr:hover td { background: #fff7f0; }
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
