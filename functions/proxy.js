const https = require('https');
const http = require('http');

exports.handler = async (event) => {
  const target = event.queryStringParameters && event.queryStringParameters.url;
  if (!target) return { statusCode: 400, body: 'No URL' };

  let targetUrl;
  try { targetUrl = new URL(target); }
  catch { return { statusCode: 400, body: 'Invalid URL' }; }

  const blocked = ['pornhub','xvideos','xnxx','onlyfans','brazzers','redtube','youporn','xhamster'];
  if (blocked.some(b => targetUrl.hostname.includes(b))) return { statusCode: 403, body: 'Blocked' };

  return new Promise((resolve) => {
    const proto = targetUrl.protocol === 'https:' ? https : http;
    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: event.httpMethod || 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Referer': targetUrl.origin,
      }
    };

    const req = proto.request(options, (res) => {
      if ([301,302,303,307,308].includes(res.statusCode)) {
        const loc = res.headers['location'];
        if (loc) {
          try {
            const abs = new URL(loc, targetUrl).toString();
            return resolve({
              statusCode: 302,
              headers: { Location: '/?url=' + encodeURIComponent(abs) },
              body: ''
            });
          } catch(e) {}
        }
      }

      const ct = res.headers['content-type'] || '';
      let body = '';
      res.setEncoding('utf8');
      res.on('data', c => body += c);
      res.on('end', () => {
        if (!ct.includes('text/html')) {
          return resolve({
            statusCode: res.statusCode,
            headers: {
              'Content-Type': ct,
              'Access-Control-Allow-Origin': '*'
            },
            body,
            isBase64Encoded: false
          });
        }

        const origin = targetUrl.origin;
        const P = '/.netlify/functions/proxy?url=';

        const rewrite = (u) => {
          if (!u || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#') || u.startsWith('mailto:')) return u;
          try {
            let abs;
            if (u.startsWith('//')) abs = targetUrl.protocol + u;
            else if (u.startsWith('/')) abs = origin + u;
            else if (!u.startsWith('http')) abs = origin + '/' + u;
            else abs = u;
            return P + encodeURIComponent(abs);
          } catch(e) { return u; }
        };

        body = body.replace(/(src|href|action)=["']([^"']*?)["']/gi, (m, attr, val) => {
          if (['mailto:', 'tel:', '#', 'javascript:'].some(p => val.startsWith(p))) return m;
          const q = m.includes('"') ? '"' : "'";
          return `${attr}=${q}${rewrite(val)}${q}`;
        });

        const inject = `<base href="${origin}/"><script>
(function(){
  var P='/.netlify/functions/proxy?url=',O='${origin}',T='${targetUrl.protocol}';
  function abs(u){
    if(!u||u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('#'))return u;
    if(u.startsWith('//'))return T+u;
    if(u.startsWith('/'))return O+u;
    if(!u.startsWith('http'))return O+'/'+u;
    return u;
  }
  var _f=window.fetch;
  window.fetch=function(inp,init){
    try{var u=typeof inp==='string'?inp:inp.url;if(u&&!u.includes(location.hostname)){inp=P+encodeURIComponent(abs(u));}}catch(e){}
    return _f.apply(this,arguments);
  };
  var _x=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    try{if(u&&typeof u==='string'&&!u.includes(location.hostname)){u=P+encodeURIComponent(abs(u));}}catch(e){}
    return _x.apply(this,arguments);
  };
  document.addEventListener('click',function(e){
    var a=e.target.closest('a[href]');if(!a)return;
    var h=a.getAttribute('href');
    if(!h||h.startsWith('#')||h.startsWith('javascript:')||h.startsWith('mailto:'))return;
    var ab=abs(h);
    if(ab.startsWith('http')&&!ab.includes(location.hostname)){e.preventDefault();location.href=P+encodeURIComponent(ab);}
  },true);
})();
<\/script>`;

        body = body.replace(/<head[^>]*>/i, m => m + inject);
        body = body.replace(/<meta[^>]*content-security-policy[^>]*>/gi, '');

        resolve({
          statusCode: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          },
          body
        });
      });
    });

    req.on('error', (e) => {
      resolve({
        statusCode: 502,
        headers: { 'Content-Type': 'text/html' },
        body: `<html><body style="background:#0a0a0a;color:#f0f0f0;font-family:sans-serif;padding:40px"><h2 style="color:#ff2d2d">Could not reach site</h2><p>${targetUrl.hostname} refused.</p></body></html>`
      });
    });

    req.end();
  });
};
