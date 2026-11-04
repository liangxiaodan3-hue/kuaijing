const CACHE = 'kuaixing-v29';
const KEEP = ['kj-comic-pages-v1'];
const SHELL = ['index.html','style.css','app.js','manifest.json','icons/icon-192.png','icons/icon-512.png','icons/apple-touch-icon.png','index/v91_index.json'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE && KEEP.indexOf(k) < 0).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  const isCode = /\.(?:js|css|html|json)$/.test(url.pathname) || e.request.mode === 'navigate';
  if (isCode) {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(e.request);
        caches.open(CACHE).then(c => c.put(e.request, fresh.clone())).catch(() => {});
        return fresh;
      } catch (err) {
        const hit = await caches.match(e.request, { ignoreSearch: true });
        return hit || Response.error();
      }
    })());
  } else {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
  }
});

