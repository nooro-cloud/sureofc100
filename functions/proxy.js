const https = require('https');
const http = require('http');
const url = require('url');

const BLOCKED = ['pornhub','xvideos','xnxx','onlyfans','brazzers','redtube','youporn','xhamster'];

exports.handler = async (event) => {
  const target = event.queryStringParameters && event.queryStringParameters.url;
  if (!target) return { statusCode: 200, headers: {'Content-Type':'text/plain'}, body: 'Alert Proxy Online' };

  let targetUrl;
  try { targetUrl = new URL(target); }
  catch { return { statusCode: 400, body: 'Invalid URL' }; }

  if (BLOCKED.some(b => targetUrl.hostname.includes(b))) return { statusCode: 403, body: 'Blocked' };

  return new Promise((resolve) => {
    const proto = targetUrl.protocol === 'https:' ? https : http;
    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      path: targetUrl.pathname + (targetUrl.search || ''),
      method: event.httpMethod || 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer': targetUrl.origin,
        'Origin': targetUrl.origin,
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Site': 'cross-site',
      }
    };

    const req = proto.request(options, (res) => {
      // Handle redirects
      if ([301,302,303,307,308].includes(res.statusCode)) {
        const loc = res.headers['location'];
        if (loc) {
          try {
            const abs = new URL(loc, targetUrl).toString();
            return resolve({
              statusCode: 302,
              headers: { 'Location': '/.netlify/functions/proxy?url=' + encodeURIComponent(abs) },
              body: ''
            });
          } catch(e) {}
        }
      }

      const ct = res.headers['content-type'] || '';
      const isHTML = ct.includes('text/html');
      const isCSS = ct.includes('text/css');
      const isJS = ct.includes('javascript');

      // Collect body
      let chunks = [];
      res.on('data', c => chunks.push(Buffer.from(c)));
      res.on('end', () => {
        const rawBody = Buffer.concat(chunks);

        // Binary files — pass through directly as base64
        if (!isHTML && !isCSS && !isJS) {
          return resolve({
            statusCode: res.statusCode || 200,
            headers: {
              'Content-Type': ct || 'application/octet-stream',
              'Access-Control-Allow-Origin': '*',
              'Cache-Control': 'public, max-age=3600',
            },
            body: rawBody.toString('base64'),
            isBase64Encoded: true
          });
        }

        let body = rawBody.toString('utf8');
        const origin = targetUrl.origin;
        const P = '/.netlify/functions/proxy?url=';

        const rewrite = (u) => {
          if (!u) return u;
          u = u.trim();
          if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#') || u.startsWith('mailto:') || u.startsWith('tel:')) return u;
          try {
            let abs;
            if (u.startsWith('//')) abs = targetUrl.protocol + u;
            else if (u.startsWith('/')) abs = origin + u;
            else if (!u.startsWith('http')) abs = origin + '/' + u;
            else abs = u;
            return P + encodeURIComponent(abs);
          } catch(e) { return u; }
        };

        if (isCSS) {
          // Rewrite CSS url() and @import
          body = body.replace(/@import\s+["']([^"']+)["']/gi, (m, u) => `@import "${rewrite(u)}"`);
          body = body.replace(/url\(["']?([^"')]+)["']?\)/gi, (m, u) => `url("${rewrite(u)}")`);
          return resolve({
            statusCode: 200,
            headers: { 'Content-Type': 'text/css', 'Access-Control-Allow-Origin': '*' },
            body
          });
        }

        if (isJS) {
          // Light JS rewrite — fix absolute URL strings
          body = body.replace(/["'](https?:\/\/[^"']+)["']/g, (m, u) => {
            if (u.includes(targetUrl.hostname)) return m;
            const q = m[0];
            return q + rewrite(u) + q;
          });
          return resolve({
            statusCode: 200,
            headers: { 'Content-Type': 'application/javascript', 'Access-Control-Allow-Origin': '*' },
            body
          });
        }

        // HTML rewrite
        // Rewrite all attribute URLs
        body = body.replace(/(src|href|action|data-src|data-href|poster)=(["'])([^"']*?)\2/gi, (m, attr, q, val) => {
          if (['mailto:', 'tel:', '#', 'javascript:'].some(p => val.startsWith(p))) return m;
          return `${attr}=${q}${rewrite(val)}${q}`;
        });

        // Rewrite srcset
        body = body.replace(/srcset=(["'])([^"']+)\1/gi, (m, q, srcset) => {
          const rewritten = srcset.split(',').map(part => {
            const trimmed = part.trim();
            const spaceIdx = trimmed.search(/\s/);
            if (spaceIdx === -1) return rewrite(trimmed);
            return rewrite(trimmed.slice(0, spaceIdx)) + trimmed.slice(spaceIdx);
          }).join(', ');
          return `srcset=${q}${rewritten}${q}`;
        });

        // Rewrite inline style url()
        body = body.replace(/style=(["'])([^"']*?)\1/gi, (m, q, style) => {
          const rewritten = style.replace(/url\(["']?([^"')]+)["']?\)/gi, (sm, u) => `url("${rewrite(u)}")`);
          return `style=${q}${rewritten}${q}`;
        });

        // Remove CSP and X-Frame-Options meta tags
        body = body.replace(/<meta[^>]*content-security-policy[^>]*>/gi, '');
        body = body.replace(/<meta[^>]*x-frame-options[^>]*>/gi, '');

        // Inject interception script
        const inject = `<base href="${origin}/">
<script>
(function(){
  var P='/.netlify/functions/proxy?url=';
  var O='${origin}';
  var T='${targetUrl.protocol}';
  var H=location.hostname;

  function abs(u){
    if(!u||u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('#')||u.startsWith('javascript:'))return u;
    if(u.startsWith('//'))return T+u;
    if(u.startsWith('/'))return O+u;
    if(!u.startsWith('http'))return O+'/'+u;
    return u;
  }
  function prox(u){
    var a=abs(u);
    if(!a||!a.startsWith('http'))return a;
    return P+encodeURIComponent(a);
  }

  // Intercept fetch
  var _f=window.fetch;
  window.fetch=function(inp,init){
    try{
      var u=typeof inp==='string'?inp:(inp&&inp.url?inp.url:'');
      if(u&&!u.includes(H)&&!u.startsWith('data:')&&!u.startsWith('blob:')){
        var p=prox(u);
        inp=typeof inp==='string'?p:new Request(p,{method:inp.method,headers:inp.headers,body:inp.body,mode:'cors'});
      }
    }catch(e){}
    return _f.apply(this,arguments);
  };

  // Intercept XHR
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    try{
      if(u&&typeof u==='string'&&!u.includes(H)&&!u.startsWith('data:')){
        u=prox(u);
      }
    }catch(e){}
    var args=Array.prototype.slice.call(arguments);
    args[1]=u;
    return _xo.apply(this,args);
  };

  // Intercept clicks
  document.addEventListener('click',function(e){
    var a=e.target.closest('a[href]');
    if(!a)return;
    var h=a.getAttribute('href');
    if(!h||h.startsWith('#')||h.startsWith('javascript:')||h.startsWith('mailto:'))return;
    var ab=abs(h);
    if(ab.startsWith('http')&&!ab.includes(H)){
      e.preventDefault();
      e.stopPropagation();
      location.href=prox(ab);
    }
  },true);

  // Intercept form submit
  document.addEventListener('submit',function(e){
    var f=e.target;
    var action=f.action||location.href;
    if(action&&!action.includes(H)){
      e.preventDefault();
      var fd=new FormData(f);
      var p=new URLSearchParams(fd).toString();
      var dest=f.method&&f.method.toLowerCase()==='get'&&p?action+'?'+p:action;
      location.href=prox(dest);
    }
  },true);

  // Intercept history
  var _ps=history.pushState;
  history.pushState=function(s,t,u){
    if(u&&typeof u==='string'&&!u.includes(H)){
      var ab=abs(u);
      if(ab.startsWith('http'))u=prox(ab);
    }
    return _ps.call(this,s,t,u);
  };

  // Fix dynamically added images/iframes/scripts
  var _ob=MutationObserver;
  try{
    var mo=new _ob(function(muts){
      muts.forEach(function(mut){
        mut.addedNodes.forEach(function(node){
          if(!node.tagName)return;
          var t=node.tagName.toLowerCase();
          if((t==='img'||t==='script'||t==='iframe'||t==='source')&&node.src&&!node.src.includes(H)){
            node.src=prox(node.src);
          }
          if(t==='link'&&node.href&&!node.href.includes(H)){
            node.href=prox(node.href);
          }
        });
      });
    });
    mo.observe(document.documentElement,{childList:true,subtree:true});
  }catch(e){}
})();
<\/script>`;

        if (/<head[^>]*>/i.test(body)) {
          body = body.replace(/<head[^>]*>/i, m => m + inject);
        } else {
          body = inject + body;
        }

        resolve({
          statusCode: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'X-Frame-Options': 'ALLOWALL',
          },
          body
        });
      });
    });

    req.on('error', () => {
      resolve({
        statusCode: 502,
        headers: {'Content-Type':'text/html'},
        body: `<html><body style="background:#0a0a0a;color:#f0f0f0;font-family:sans-serif;padding:40px"><h2 style="color:#ff2d2d">Could not reach site</h2><p>${targetUrl.hostname} refused the connection.</p></body></html>`
      });
    });

    req.end();
  });
};
