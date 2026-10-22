// Minimal web proxy. Local:  node server.js  ->  http://localhost:8080
// Hosted: the host sets PORT. Requires Node 18+. No npm install needed.
const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 8080;
const HOST = process.env.PORT ? '0.0.0.0' : '127.0.0.1';
const RATE_LIMIT = 120; // requests per minute per IP
const MAX_BODY = 5e6;
const STRIP = ['content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'content-encoding', 'content-length', 'transfer-encoding',
  'strict-transport-security', 'set-cookie', 'location'];

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

// Manual redirects so every hop is checked against private ranges
async function safeFetch(url, opts) {
  for (let hop = 0; hop < 6; hop++) {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Only http/https allowed');
    const addrs = await dns.lookup(u.hostname, { all: true });
    if (addrs.some(a => isPrivate(a.address))) throw new Error('Blocked: private address');
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
setInterval(() => hits.clear(), 60000);
const limited = ip => { const n = (hits.get(ip) || 0) + 1; hits.set(ip, n); return n > RATE_LIMIT; };

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

// Runs inside every proxied page: reroutes runtime fetch/XHR/window.open/GET forms
const clientScript = base => `<script>(function(){
var B=${JSON.stringify(base).replace(/</g, '\\u003c')};
function P(u){try{if(typeof u==='string'&&u.indexOf('/proxy?url=')===0)return u;
var a=new URL(u,B);return '/proxy?url='+encodeURIComponent(a.href)}catch(e){return u}}
var of=window.fetch;window.fetch=function(i,o){
if(typeof i==='string'||i instanceof URL)i=P(String(i));else if(i instanceof Request)i=new Request(P(i.url),i);
return of.call(this,i,o)};
var ox=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){arguments[1]=P(String(u));return ox.apply(this,arguments)};
var oo=window.open;window.open=function(u){if(u)arguments[0]=P(String(u));return oo.apply(this,arguments)};
document.addEventListener('submit',function(e){
var f=e.target;if((f.method||'get').toLowerCase()!=='get')return;
var orig;try{orig=new URL(f.getAttribute('action')||'',location.href).searchParams.get('url')}catch(x){}
e.preventDefault();var u=new URL(orig||B);
new FormData(f).forEach(function(v,k){if(typeof v==='string')u.searchParams.set(k,v)});
location.href=P(u.href)},true);
})();</script>`;

function rewriteHtml(html, base) {
  let out = html
    .replace(/\b(href|src|action)=("|')(?!#|data:|javascript:|mailto:)(.*?)\2/gi,
      (m, attr, q, val) => `${attr}=${q}${proxify(val, base)}${q}`)
    .replace(/\bsrcset=("|')(.*?)\1/gi, (m, q, val) => `srcset=${q}` +
      val.split(',').map(s => { const p = s.trim().split(/\s+/); p[0] = proxify(p[0], base); return p.join(' '); }).join(', ') + q)
    .replace(/url\((['"]?)(?!data:)(.*?)\1\)/gi,
      (m, q, val) => `url(${q}${proxify(val, base)}${q})`);
  const inject = clientScript(base);
  return /<head[^>]*>/i.test(out) ? out.replace(/<head[^>]*>/i, m => m + inject) : inject + out;
}

function rewriteCss(css, base) {
  return css.replace(/url\((['"]?)(?!data:)(.*?)\1\)/gi,
    (m, q, val) => `url(${q}${proxify(val, base)}${q})`);
}

// ---- Server -----------------------------------------------------------
http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://localhost:${PORT}`);
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  if (reqUrl.pathname === '/') {
    res.setHeader('Content-Type', 'text/html');
    return fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
  }

  if (reqUrl.pathname === '/proxy') {
    if (limited(ip)) { res.writeHead(429); return res.end('Rate limit exceeded'); }
    if (!['GET', 'POST'].includes(req.method)) { res.writeHead(405); return res.end('Method not allowed'); }
    const target = reqUrl.searchParams.get('url');
    if (!/^https?:\/\//i.test(target || '')) { res.writeHead(400); return res.end('Bad or missing url'); }
    try {
      const opts = { method: req.method, headers: { 'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0' } };
      if (req.method === 'POST') {
        opts.body = await readBody(req);
        if (req.headers['content-type']) opts.headers['Content-Type'] = req.headers['content-type'];
      }
      const { res: upstream, url: finalUrl } = await safeFetch(target, opts);
      const type = upstream.headers.get('content-type') || '';
      upstream.headers.forEach((v, k) => { if (!STRIP.includes(k.toLowerCase())) res.setHeader(k, v); });

      if (type.includes('text/html')) {
        res.writeHead(upstream.status);
        return res.end(rewriteHtml(await upstream.text(), finalUrl));
      }
      if (type.includes('text/css')) {
        res.writeHead(upstream.status);
        return res.end(rewriteCss(await upstream.text(), finalUrl));
      }
      res.writeHead(upstream.status);
      return res.end(Buffer.from(await upstream.arrayBuffer()));
    } catch (e) {
      res.writeHead(502); return res.end('Fetch failed: ' + e.message);
    }
  }

  res.writeHead(404); res.end('Not found');
}).listen(PORT, HOST, () => console.log(`Proxy running on ${HOST}:${PORT}`));
