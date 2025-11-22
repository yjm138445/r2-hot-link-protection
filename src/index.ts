// 修改这个列表，更新为自己的 domain list
const ALLOWED = new Set([
  'www.dm147.cc',
  'play.dm147.cc',
  'www.556ys.com'
]);
const CORP    = 'same-site';     // same-origin 也行
const BUCKET  = 'MEDIA';         // 对应 wrangler 的 r2_buckets 绑定名

export default {
  async fetch(request: Request, env: Env) {
    console.log('Received request:', request.method, request.url);

    /* 0. 读取 Referer 并做白名单校验 */
    const refererHeader = request.headers.get('Referer') || '';
    const originHeader = request.headers.get('Origin') || '';
    let refererHost = '';
    let refererOrigin = '';
    
    // 增强的域名验证逻辑
    console.log('Headers received:', { referer: refererHeader, origin: originHeader });
    
    // 1. 尝试从Referer头解析 - 更健壮的处理
    try {
      if (refererHeader) {
        const url = new URL(refererHeader);
        refererHost = url.hostname.toLowerCase(); // 转换为小写以确保大小写不敏感的匹配
        refererOrigin = url.origin;
        console.log('Parsed Referer host:', refererHost);
      }
    } catch (e) {
      console.error('Error parsing Referer:', e, 'Referer value:', refererHeader);
    }

    // 2. 如果没有获取到Referer，尝试从Origin头获取
    if (!refererHost && originHeader) {
      try {
        const url = new URL(originHeader);
        refererHost = url.hostname.toLowerCase();
        refererOrigin = originHeader;
        console.log('Parsed Origin host:', refererHost);
      } catch (e) {
        console.error('Error parsing Origin:', e, 'Origin value:', originHeader);
      }
    }
    
    // 3. 特殊处理：检查是否是白名单中的域名，但格式可能有细微差异
    if (!refererHost && (refererHeader || originHeader)) {
      console.log('Fallback check for whitelist domains...');
      const checkStr = (refererHeader || originHeader).toLowerCase();
      for (const allowedDomain of ALLOWED) {
        if (checkStr.includes(allowedDomain)) {
          refererHost = allowedDomain;
          refererOrigin = `https://${allowedDomain}`; // 设置一个标准的origin
          console.log('Fallback matched allowed domain:', allowedDomain);
          break;
        }
      }
    }

    // 3. 精确检查域名：
    //    - 只允许带有白名单域名Referer/Origin的请求访问
    //    - 阻止没有Referer或Referer不在白名单中的请求
    const isAllowed = refererHost && ALLOWED.has(refererHost);
    console.log('Access check:', { isAllowed, refererHost });
    
    if (!isAllowed) {
      // 4. 输出错误信息 - 更详细的诊断
      let blockedReason;
      if (refererHost) {
        blockedReason = `blocked: ${refererHost} (not in whitelist)`;
      } else if (refererHeader || originHeader) {
        blockedReason = `blocked: could not validate domain from headers`;
      } else {
        blockedReason = 'blocked: no referer';
      }
      console.log(blockedReason, { refererHeader, originHeader });
      return new Response(blockedReason, {
        status: 403,
        headers: {
          'Content-Type': 'text/plain'
        }
      });
    }

    /* 0-bis. 预检请求处理 */
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin':  refererOrigin,
          'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': 'Range',
          'Access-Control-Max-Age':       '86400'
        }
      });
    }
    
    /* 1. 解析对象 Key */
    let key = '';
    try {
      const url = new URL(request.url);
      key = decodeURIComponent(url.pathname.slice(1));
      console.log('Requested key:', key);
      if (!key) {
        console.log('Bad request: empty key');
        return new Response('bad request', { status: 400 });
      }
    } catch (e) {
      console.error('Error parsing URL:', e);
      return new Response('invalid request', { status: 400 });
    }

    /* 2. 处理 Range（播放器基本都会带） */
    const range = request.headers.get('Range');
    let opts: R2GetOptions | undefined;
    if (range) {
      const m = /bytes=(\d+)-(\d*)/.exec(range);
      if (m) {
        const [ , s, e ] = m;
        opts = { range: { offset: +s, length: e ? (+e - +s + 1) : undefined }};
      }
    }

    /* 3. 读取 R2 */
    let obj;
    try {
      obj = await env[BUCKET].get(key, opts);
      console.log('R2 get result:', obj ? 'success' : 'not found');
      if (!obj) {
        console.log(`Object not found: ${key}`);
        return new Response('404', { status: 404 });
      }
    } catch (e) {
      console.error('Error reading from R2:', e);
      return new Response('server error', { status: 500 });
    }

    /* 4. 生成响应 + CORS/CORP 头 */
    const h = new Headers(obj.httpMetadata);
    // h.set('Cross-Origin-Resource-Policy', CORP); // 如果 worker 与目标域名在同一个根域名下，可以考虑打开
    h.set('Access-Control-Allow-Origin',  refererOrigin);
    h.set('Access-Control-Allow-Credentials', 'true');
    h.set('Vary',                         'Origin');          // 避免缓存污染
    h.set('Access-Control-Expose-Headers','Content-Length, Content-Range, Accept-Ranges');

    if (range && opts?.range) {
      const size   = obj.size;
      const start  = opts.range.offset;
      const endPos = opts.range.length ? start + opts.range.length - 1 : size - 1;
      h.set('Accept-Ranges', 'bytes');
      h.set('Content-Range', `bytes ${start}-${endPos}/${size}`);
      return new Response(obj.body, { status: 206, headers: h });
    }

    return new Response(obj.body, { headers: h });
  }
}

