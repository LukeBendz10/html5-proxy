// Web proxy with WebSocket tunneling.
// Local:   npm install && node server.js   ->  http://localhost:8080
// Hosted:  the host sets PORT. Requires Node 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const dns = require('dns').promises;
const net = require('net');
const { Readable } = require('stream');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = process.env.PORT || 8080;
const HOST = process.env.PORT ? '0.0.0.0' : '127.0.0.1';
const RATE_LIMIT = 600;          // HTTP requests per minute per IP (pages load many assets)
const MAX_BODY = 5e6;            // max POST body
const MAX_WS_PER_IP = 6;         // simultaneous WebSocket tunnels per IP
const MAX_WS_MSG = 2 * 1024 * 1024;
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
const STRIP = ['content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'content-encoding', 'content-length', 'transfer-encoding',
  'connection', 'keep-alive', 'upgrade', 'strict-transport-security', 'set-cookie',
  'location', 'cross-origin-embedder-policy', 'cross-origin-opener-policy',
  'cross-origin-resource-policy', 'permissions-policy', 'report-to', 'nel'];
const COMPRESSIBLE = /^(text\/|application\/(javascript|x-javascript|json|xml|wasm)|image\/svg)/;

// ---- Guardrails -------------------------------------------------------
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
           (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
           (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') ||
         l.startsWith('fe80') || l.startsWith('::ffff:');
}

async function assertPublic(hostname) {
  const addrs = await dns.lookup(hostname, { all: true });
  if (addrs.some(a => isPrivate(a.address))) throw new Error('Blocked: private address');
}

// Manual redirects so every hop is checked against private ranges
async function safeFetch(url, opts) {
  for (let hop = 0; hop < 6; hop++) {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Only http/https allowed');
    await assertPublic(u.hostname);
    const res = await fetch(url, { ...opts, redirect: 'manual' });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      url = new URL(loc, url).href;
      if ([301, 302, 303].includes(res.status)) opts = { ...opts, method: 'GET', body: undefined };
      continue;
    }
    return { res, url };
  }
  throw new Error('Too many redirects');
}

const hits = new Map();
const wsCount = new Map();
setInterval(() => hits.clear(), 60000);
const limited = ip => { const n = (hits.get(ip) || 0) + 1; hits.set(ip, n); return n > RATE_LIMIT; };
const clientIp = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

const readBody = req => new Promise((resolve, reject) => {
  const chunks = []; let n = 0;
  req.on('data', d => { n += d.length; if (n > MAX_BODY) { reject(new Error('Body too large')); req.destroy(); } else chunks.push(d); });
  req.on('end', () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

// ---- Rewriting --------------------------------------------------------
const proxify = (u, base) => {
  try { return '/proxy?url=' + encodeURIComponent(new URL(u, base).href); }
  catch { return u; }
};

// Runs first inside every proxied page: reroutes runtime requests back through the proxy.
const CLIENT = String.raw`<script>(function(){
var B=__BASE__,LO=location.origin;
function P(u){u=String(u);
 if(u.charAt(0)==='#'||u.indexOf('/proxy?url=')===0)return u;
 try{var x=new URL(u);if(x.origin===LO&&x.pathname==='/proxy')return u}catch(e){}
 try{var a=new URL(u,B);if(a.protocol!=='http:'&&a.protocol!=='https:')return u;
  return '/proxy?url='+encodeURIComponent(a.href)}catch(e){return u}}
try{var of=window.fetch;window.fetch=function(i,o){
 try{if(typeof i==='string'||i instanceof URL)i=P(i);else if(i&&i.url)i=new Request(P(i.url),i)}catch(e){}
 return of.call(this,i,o)}}catch(e){}
try{var ox=XMLHttpRequest.prototype.open;
 XMLHttpRequest.prototype.open=function(m,u){arguments[1]=P(u);return ox.apply(this,arguments)}}catch(e){}
try{var sb=navigator.sendBeacon;if(sb)navigator.sendBeacon=function(u,d){return sb.call(this,P(u),d)}}catch(e){}
try{var oo=window.open;window.open=function(u){if(u)arguments[0]=P(u);return oo.apply(this,arguments)}}catch(e){}
try{var OW=window.WebSocket;
 var WS=function(u,p){var a=new URL(String(u),B);
  if(a.protocol==='http:')a.protocol='ws:';else if(a.protocol==='https:')a.protocol='wss:';
  var s=(location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws?url='+encodeURIComponent(a.href)+'&origin='+encodeURIComponent(new URL(B).origin);
  return p===undefined?new OW(s):new OW(s,p)};
 WS.prototype=OW.prototype;WS.CONNECTING=0;WS.OPEN=1;WS.CLOSING=2;WS.CLOSED=3;window.WebSocket=WS}catch(e){}
function W(proto,prop){var d=Object.getOwnPropertyDescriptor(proto,prop);if(!d||!d.set)return;
 Object.defineProperty(proto,prop,{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){d.set.call(this,P(v))}})}
[[HTMLScriptElement,'src'],[HTMLImageElement,'src'],[HTMLIFrameElement,'src'],[HTMLLinkElement,'href'],
 [HTMLMediaElement,'src'],[HTMLSourceElement,'src'],[HTMLEmbedElement,'src'],[HTMLFormElement,'action']
].forEach(function(p){try{W(p[0].prototype,p[1])}catch(e){}});
try{var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){
 if(typeof n==='string'&&/^(src|href|action|poster|data)$/i.test(n)&&this.tagName!=='A'&&this.tagName!=='BASE')v=P(v);
 return sa.call(this,n,v)}}catch(e){}
try{var ps=history.pushState,rs=history.replaceState;
 history.pushState=function(a,b){try{return ps.call(this,a,b)}catch(e){}};
 history.replaceState=function(a,b){try{return rs.call(this,a,b)}catch(e){}}}catch(e){}
document.addEventListener('submit',function(e){
 var f=e.target;if(!f||(f.method||'get').toLowerCase()!=='get')return;
 var orig;try{orig=new URL(f.getAttribute('action')||'',location.href).searchParams.get('url')}catch(x){}
 e.preventDefault();var u=new URL(orig||B);
 new FormData(f).forEach(function(v,k){if(typeof v==='string')u.searchParams.set(k,v)});
 location.href=P(u.href)},true);
})();</script>`;

function rewriteHtml(html, base) {
  const out = html
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy[^>]*>/gi, '')
    .replace(/\b(href|src|action)=("|')(?!#|data:|blob:|javascript:|mailto:)(.*?)\2/gi,
      (m, attr, q, val) => `${attr}=${q}${proxify(val, base)}${q}`)
    .replace(/\bsrcset=("|')(.*?)\1/gi, (m, q, val) => `srcset=${q}` +
      val.split(',').map(s => { const p = s.trim().split(/\s+/); p[0] = proxify(p[0], base); return p.join(' '); }).join(', ') + q)
    .replace(/url\((['"]?)(?!data:|blob:)(.*?)\1\)/gi,
      (m, q, val) => `url(${q}${proxify(val, base)}${q})`);
  const inject = CLIENT.replace('__BASE__', () => JSON.stringify(base).replace(/</g, '\\u003c'));
  return /<head[^>]*>/i.test(out) ? out.replace(/<head[^>]*>/i, m => m + inject) : inject + out;
}

const rewriteCss = (css, base) => css.replace(/url\((['"]?)(?!data:|blob:)(.*?)\1\)/gi,
  (m, q, val) => `url(${q}${proxify(val, base)}${q})`);

// ---- Cache: static assets are kept in memory so repeat loads skip the upstream fetch + compression
const cache = new Map();
let cacheBytes = 0;
const CACHE_MAX = 60e6, CACHE_ITEM_MAX = 8e6, CACHE_TTL = 20 * 60e3;
const CACHEABLE = /^(image\/|font\/|audio\/|model\/|application\/(wasm|javascript|x-javascript|font-woff2?|vnd\.ms-fontobject)|text\/(javascript|css))/;

function cacheDrop(key) {
  const e = cache.get(key);
  if (e) { cacheBytes -= e.size; cache.delete(key); }
}
function cacheGet(key) {
  const e = cache.get(key);
  if (!e) return null;
  if (e.exp < Date.now()) { cacheDrop(key); return null; }
  cache.delete(key); cache.set(key, e); // refresh LRU order
  return e;
}
function cachePut(key, e) {
  if (e.raw.length > CACHE_ITEM_MAX) return;
  cacheDrop(key);
  while (cacheBytes + e.size > CACHE_MAX && cache.size) cacheDrop(cache.keys().next().value);
  e.key = key; cache.set(key, e); cacheBytes += e.size;
}

const applyHdrs = (res, hdrs) => { for (const [k, v] of Object.entries(hdrs)) { try { res.setHeader(k, v); } catch {} } };

// Send a buffered body, gzip at level 1 (cheap on a weak CPU); the compressed copy is cached too
function serveEntry(req, res, e) {
  applyHdrs(res, e.hdrs);
  const wantsGz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && e.raw.length > 1024 && COMPRESSIBLE.test(e.mime);
  if (!wantsGz) { res.writeHead(e.status); return res.end(e.raw); }
  res.setHeader('Content-Encoding', 'gzip');
  res.setHeader('Vary', 'Accept-Encoding');
  if (e.gz) { res.writeHead(e.status); return res.end(e.gz); }
  zlib.gzip(e.raw, { level: 1 }, (err, out) => {
    if (err) { res.removeHeader('Content-Encoding'); res.writeHead(e.status); return res.end(e.raw); }
    e.gz = out;
    if (e.key && cache.get(e.key) === e) { e.size += out.length; cacheBytes += out.length; }
    res.writeHead(e.status); res.end(out);
  });
}

function finish(req, res, status, mime, hdrs, buf, key) {
  const e = { status, mime, hdrs, raw: buf, gz: null, size: buf.length, exp: Date.now() + CACHE_TTL };
  if (key) cachePut(key, e);
  return serveEntry(req, res, e);
}

// ---- HTTP proxy -------------------------------------------------------
async function handleProxy(req, res, reqUrl) {
  const t0 = Date.now();
  if (limited(clientIp(req))) { res.writeHead(429); return res.end('Rate limit exceeded'); }
  if (!METHODS.includes(req.method)) { res.writeHead(405); return res.end('Method not allowed'); }
  const target = reqUrl.searchParams.get('url');
  if (!/^https?:\/\//i.test(target || '')) { res.writeHead(400); return res.end('Bad or missing url'); }

  const plainGet = req.method === 'GET' && !req.headers.range;
  if (plainGet) { const hit = cacheGet(target); if (hit) return serveEntry(req, res, hit); }

  try {
    const t = new URL(target);
    const headers = { 'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0', 'Referer': t.origin + '/' };
    for (const h of ['accept', 'accept-language', 'range']) if (req.headers[h]) headers[h] = req.headers[h];
    const opts = { method: req.method, headers };
    if (!['GET', 'HEAD'].includes(req.method)) {
      opts.body = await readBody(req);
      headers['Origin'] = t.origin;
      if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
    }
    const { res: up, url: finalUrl } = await safeFetch(target, opts);
    const tUp = Date.now() - t0;
    const mime = (up.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    res.on('close', () => {
      const ms = Date.now() - t0;
      if (ms > 1500) console.log(`slow ${ms}ms (upstream ${tUp}ms) ${mime || '?'} ${target.slice(0, 120)}`);
    });

    const hdrs = {};
    up.headers.forEach((v, k) => { if (!STRIP.includes(k.toLowerCase())) hdrs[k.toLowerCase()] = v; });
    const len = Number(up.headers.get('content-length')) || 0;
    const canCache = plainGet && up.status === 200 && CACHEABLE.test(mime) &&
      !/no-store|private/i.test(up.headers.get('cache-control') || '') && len <= CACHE_ITEM_MAX;

    if (mime === 'text/html' || mime === 'application/xhtml+xml') {
      hdrs['content-type'] = mime + '; charset=utf-8';
      return finish(req, res, up.status, mime, hdrs, Buffer.from(rewriteHtml(await up.text(), finalUrl), 'utf8'), null);
    }
    if (mime === 'text/css') {
      hdrs['content-type'] = 'text/css; charset=utf-8';
      return finish(req, res, up.status, mime, hdrs, Buffer.from(rewriteCss(await up.text(), finalUrl), 'utf8'), canCache ? target : null);
    }
    if (req.method === 'HEAD' || !up.body) {
      applyHdrs(res, hdrs); res.writeHead(up.status); return res.end();
    }
    if (up.status !== 206 && (COMPRESSIBLE.test(mime) || canCache)) {
      return finish(req, res, up.status, mime, hdrs, Buffer.from(await up.arrayBuffer()), canCache ? target : null);
    }
    applyHdrs(res, hdrs);
    res.writeHead(up.status);
    const stream = Readable.fromWeb(up.body);
    stream.on('error', () => res.destroy());
    res.on('close', () => stream.destroy());
    stream.pipe(res);
  } catch (e) {
    if (!res.headersSent) res.writeHead(502);
    res.end('Fetch failed: ' + e.message);
  }
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, 'http://localhost');
  if (reqUrl.pathname === '/health') { res.writeHead(200); return res.end('ok'); }
  if (reqUrl.pathname === '/') {
    res.setHeader('Content-Type', 'text/html');
    return fs.createReadStream(path.join(__dirname, 'index.html')).on('error', () => res.end()).pipe(res);
  }
  if (reqUrl.pathname === '/proxy') return handleProxy(req, res, reqUrl);
  res.writeHead(404); res.end('Not found');
});

// ---- WebSocket tunnel: browser <-> /ws?url=wss://game-server <-> game server ----
const sane = c => (c >= 1000 && c <= 4999 && ![1004, 1005, 1006, 1015].includes(c)) ? c : 1000;

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  const reject = (code, msg) => {
    try { socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`); } catch {}
    socket.destroy();
  };
  try {
    const u = new URL(req.url, 'http://localhost');
    const ip = clientIp(req);
    if (u.pathname !== '/ws') return reject(404, 'Not Found');
    if (limited(ip) || (wsCount.get(ip) || 0) >= MAX_WS_PER_IP) return reject(429, 'Too Many Requests');

    let t;
    try { t = new URL(u.searchParams.get('url')); } catch { return reject(400, 'Bad Request'); }
    if (!/^wss?:$/.test(t.protocol)) return reject(400, 'Bad Request');
    try { await assertPublic(t.hostname); } catch { return reject(403, 'Forbidden'); }

    let origin = t.origin.replace(/^ws/, 'http');
    try { origin = new URL(u.searchParams.get('origin')).origin; } catch {}
    const protocols = (req.headers['sec-websocket-protocol'] || '').split(',').map(s => s.trim()).filter(Boolean);

    let opened = false, client = null, counted = false;
    const release = () => {
      if (counted) { counted = false; wsCount.set(ip, Math.max(0, (wsCount.get(ip) || 1) - 1)); }
    };

    const upstream = new WebSocket(t.href, protocols, {
      headers: { 'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0' },
      origin, handshakeTimeout: 15000, maxPayload: MAX_WS_MSG,
    });
    upstream.on('error', () => {
      if (!opened) return reject(502, 'Bad Gateway');
      if (client) client.terminate();
    });
    upstream.on('open', () => {
      opened = true;
      const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_WS_MSG,
        handleProtocols: () => upstream.protocol || false });
      wss.handleUpgrade(req, socket, head, c => {
        client = c; counted = true;
        wsCount.set(ip, (wsCount.get(ip) || 0) + 1);
        c.on('message', (d, bin) => { if (upstream.readyState === WebSocket.OPEN) upstream.send(d, { binary: bin }); });
        upstream.on('message', (d, bin) => { if (c.readyState === WebSocket.OPEN) c.send(d, { binary: bin }); });
        c.on('close', (code, reason) => { try { upstream.close(sane(code), reason); } catch { upstream.terminate(); } release(); });
        upstream.on('close', (code, reason) => { try { c.close(sane(code), reason); } catch { c.terminate(); } release(); });
        c.on('error', () => upstream.terminate());
      });
    });
  } catch { reject(500, 'Server Error'); }
});

server.listen(PORT, HOST, () => console.log(`Proxy running on ${HOST}:${PORT}`));

// Keep the free Render instance awake by pinging itself. Set KEEP_ALIVE=0 to disable.
const SELF = process.env.RENDER_EXTERNAL_URL;
if (SELF && process.env.KEEP_ALIVE !== '0') {
  setInterval(() => fetch(SELF + '/health').catch(() => {}), 10 * 60 * 1000);
}
