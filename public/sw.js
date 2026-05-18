const CACHE_NAME = 'secure-password-vault-v3';
const APP_SHELL = [
  './',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png'
];
const HTML_ASSET_PATTERN = /(?:src|href)=["']\.\/([^"']+\.(?:js|css))["']/g;

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => collectShellAssets(cache).then((assets) => cache.addAll(assets)))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

async function collectShellAssets(cache) {
  try {
    const response = await fetch('./', { cache: 'reload' });
    if (!response.ok) return APP_SHELL;
    const html = await response.clone().text();
    await cache.put('./', response);
    const htmlAssets = [...html.matchAll(HTML_ASSET_PATTERN)].map((match) => `./${match[1]}`);
    return [...new Set([...APP_SHELL, ...htmlAssets])];
  } catch {
    return APP_SHELL;
  }
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
