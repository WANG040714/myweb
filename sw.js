const CACHE_NAME = 'timetable-v4';
const URLS = ['/timetable', '/timetable.html'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(URLS)));
    self.skipWaiting();
});

self.addEventListener('activate', e => {
    e.waitUntil(caches.keys().then(keys =>
        Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ));
    self.clients.claim();
});

self.addEventListener('fetch', e => {
    if (e.request.method !== 'GET') return;
    const url = new URL(e.request.url);
    if (url.origin !== self.location.origin) return;

    const forceNetwork = url.searchParams.has('_r');
    url.search = '';
    const cacheKey = url.toString();

    const updateCache = resp => {
        if (resp && resp.ok) {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then(c => c.put(cacheKey, clone));
        }
        return resp;
    };

    const network = fetch(e.request).then(updateCache);
    if (forceNetwork) {
        e.respondWith(network.catch(() => caches.match(cacheKey)));
        return;
    }

    // 缓存立即返回,网络响应只负责后台更新
    e.respondWith(
        caches.match(cacheKey).then(cached => cached || network)
    );
});
