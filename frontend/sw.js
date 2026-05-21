const CACHE_NAME = "avalia-nr01-v1";

self.addEventListener("install", (event) => {
  console.log("Service Worker instalado");
});

self.addEventListener("fetch", (event) => {
  event.respondWith(fetch(event.request));
});
