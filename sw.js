const CACHE_NAME = 'timetable-v3';
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
    e.respondWith(
        // 联网优先:调课要能立刻看到,断网才用缓存
        fetch(e.request).then(resp => {
            if (e.request.method === 'GET') {
                const clone = resp.clone();
                caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
            }
            return resp;
        }).catch(() => caches.match(e.request).then(r => r || fetch(e.request)))
    );
});