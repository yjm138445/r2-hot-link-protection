// 修改这个列表，更新为自己的 domain list
const ALLOWED = new Set([
  'www.dm147.cc',
  'www.556ys.com',
  'www.bilibili.com'
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
    
    // 1. 尝试从Referer头解析
    try {
      if (refererHeader) {
        const url = new URL(refererHeader);
        refererHost = url.hostname;
        refererOrigin = url.origin;
        console.log('Referer host:', refererHost);
      }
    } catch (e) {
      console.error('Error parsing Referer:', e);
    }

    // 2. 如果没有获取到Referer，尝试从Origin头获取
    if (!refererHost && originHeader) {
      try {
        const url = new URL(originHeader);
        refererHost = url.hostname;
        refererOrigin = originHeader;
        console.log('Using Origin host:', refererHost);
      } catch (e) {
        console.error('Error parsing Origin:', e);
      }
    }

    // 获取请求的目标主机（worker自己的域名）
    const requestHost = request.headers.get('host') || '';
    
    // 3. 检查域名：
    //    - 如果有Referer/Origin且在白名单中允许访问
    //    - 如果是直接访问worker自己的域名也允许（处理no-referrer情况）
    const isRefererAllowed = refererHost && ALLOWED.has(refererHost);
    const isDirectAccess = !refererHost && requestHost.includes('dm147.cc');
    const isAllowed = isRefererAllowed || isDirectAccess;
    
    console.log('Access check:', { isRefererAllowed, isDirectAccess, refererHost, requestHost });
    
    if (!isAllowed) {
      let blockedReason = '';
      if (refererHost) {
        blockedReason = `blocked: ${refererHost} (not in whitelist)`;
      } else if (!requestHost.includes('dm147.cc')) {
        blockedReason = `blocked: no referer and not direct access to dm147.cc`;
      } else {
        blockedReason = 'blocked: unknown reason';
      }
      console.log('Access blocked:', blockedReason);
      return new Response(blockedReason, { status: 403 });
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

