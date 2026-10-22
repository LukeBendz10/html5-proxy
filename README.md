# HTML5 Proxy: deploy + embed

## Files
- server.js     the proxy (Node 18+, zero dependencies)
- index.html    standalone proxy page (served at the server's root)
- embed.html    the snippet you paste into Google Sites
- package.json, render.yaml   deploy config

## Deploy (Render free tier, about 5 minutes)
1. Create a GitHub repo and upload server.js, index.html, package.json, render.yaml
   (GitHub: Add file > Upload files).
2. Go to render.com, sign up, then New > Web Service > connect that repo.
   Render reads render.yaml: Node, build `npm install`, start `npm start`, Free plan.
3. When it's live, copy your URL, e.g. https://html5-proxy-abcd.onrender.com
4. Visit that URL in a browser. You should see the URL bar page. Test a site.

## Embed in Google Sites
1. Open embed.html and change the PROXY line to your Render URL (no trailing slash).
2. In Google Sites: Insert > Embed > "Embed code" tab > paste the whole file > Insert.
3. Resize the embed box, then Publish.

## Notes
- Free Render services sleep after idle, so the first load can take ~30-60 seconds.
- Anyone who finds the URL can use the proxy. Rate limit is 120 req/min per IP.
- Cookies/logins are intentionally not supported.
