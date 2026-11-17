'use strict';
/**
 * 尺素 Chatgram —— 云端服务端
 *
 * 设计要点：
 *  1. 登录用 TOTP 动态密码（180 秒一换），密钥只存在于 App 本地，服务端只存校验用的副本
 *  2. 所有消息正文 AES-256-GCM 加密后落盘，直接看 db.json 是密文
 *  3. 消息 10 天到期自动销毁，销毁前 24 小时接口会返回"即将销毁"清单
 *  4. 只监听 $PORT 一个端口；存储后端可切换（本地文件 / Postgres）
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const store = require('./store');

const PORT = +(process.env.PORT || 3000);
const ROOT = __dirname;
const PUB = path.join(ROOT, 'public');
const DATA = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const UPLOADS = path.join(DATA, 'uploads');

/* ==================== 常量 ==================== */
const RETENTION_DAYS = +(process.env.RETENTION_DAYS || 10);   // 消息保留天数（测试可覆盖）
const WARN_MS = 24 * 3600 * 1000;          // 到期前多久开始提醒
const TOTP_STEP = 180;                     // 动态密码周期（秒）
const TOTP_WINDOW = 1;                     // 允许前后各一个周期的时钟偏差
const SESSION_TTL = 30 * 24 * 3600 * 1000;
const MAX_TEXT = 4000;
const MAX_FILE = +(process.env.MAX_FILE_MB || 30) * 1024 * 1024;
// 免费数据库只有 0.5GB，文件总量要设上限；0 表示不限
const MAX_FILES_BYTES = +(process.env.MAX_FILES_MB || 0) * 1024 * 1024;
const MAX_JSON = 64 * 1024;

/**
 * 允许直接从根目录取的文件（白名单）。
 * 有了它，部署时把 index.html 平铺在根目录也能跑 —— 手机上传时不用建文件夹。
 * 白名单是为了别把 server.js / .env 这类东西暴露到公网。
 */
const FLAT_FILES = new Set([
  '/index.html',
  '/manifest.webmanifest',
  '/sw.js',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable.png'
]);

/* ==================== 主密钥 ==================== */
let MASTER;

/**
 * master.key 丢了，历史消息就永远解不开。
 * 云上每次重新部署都是一台全新的机器，磁盘不可靠 ——
 * 所以优先用环境变量，其次数据库里存一份，最后才现生成。
 */
async function initMaster() {
  if (process.env.MASTER_KEY && /^[0-9a-f]{64}$/i.test(process.env.MASTER_KEY)) {
    MASTER = Buffer.from(process.env.MASTER_KEY, 'hex');
    return 'env';
  }
  const old = await store.loadSecret('master.key');
  if (old && /^[0-9a-f]{64}$/i.test(old)) {
    MASTER = Buffer.from(old, 'hex');
    return 'db';
  }
  MASTER = crypto.randomBytes(32);
  await store.saveSecret('master.key', MASTER.toString('hex'));
  return 'new';
}

function seal(str) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', MASTER, iv);
  const ct = Buffer.concat([c.update(Buffer.from(String(str), 'utf8')), c.final()]);
  return 'v1.' + iv.toString('base64url') + '.' + c.getAuthTag().toString('base64url') + '.' + ct.toString('base64url');
}
function unseal(s) {
  if (typeof s !== 'string' || !s.startsWith('v1.')) return s;
  const p = s.split('.');
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', MASTER, Buffer.from(p[1], 'base64url'));
    d.setAuthTag(Buffer.from(p[2], 'base64url'));
    return Buffer.concat([d.update(Buffer.from(p[3], 'base64url')), d.final()]).toString('utf8');
  } catch (e) {
    return '';
  }
}

/* ==================== 数据 ==================== */
let db = { users: [], msgs: [], sessions: [], seq: 0 };

/** 只排队，真正落盘由 store 合并后再写 */
function save() { store.saveDb(db); }

/* ==================== Base32 / TOTP ==================== */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32dec(s) {
  s = String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, val = 0;
  const out = [];
  for (const ch of s) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
function totpCounter() { return Math.floor(Date.now() / 1000 / TOTP_STEP); }
function checkTotp(key, code) {
  code = String(code || '').replace(/\D/g, '');
  if (code.length !== 6 || !key) return 0;
  const now = totpCounter();
  for (let w = -TOTP_WINDOW; w <= TOTP_WINDOW; w++) {
    const c = now + w;
    if (c < 0) continue;
    if (hotp(key, c) === code) return c;
  }
  return 0;
}

/* 已用过的动态码，防重放 */
const used = new Map();
function markUsed(uid, c) { used.set(uid + ':' + c, Date.now() + TOTP_STEP * 1000 * 4); }
function wasUsed(uid, c) { const t = used.get(uid + ':' + c); return !!t && t > Date.now(); }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of used) if (v <= now) used.delete(k);
}, 60 * 1000);

/* ==================== 小工具 ==================== */
const uid = () => crypto.randomBytes(9).toString('hex');
const nowMs = () => Date.now();

function json(res, code, obj, extra) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store'
  }, extra || {}));
  res.end(body);
}
function fail(res, code, msg) { json(res, code, { error: msg }); }

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', c => {
      n += c.length;
      if (n > limit) { reject(Object.assign(new Error('过大'), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const b = await readBody(req, MAX_JSON);
  if (!b.length) return {};
  try { return JSON.parse(b.toString('utf8')); } catch (e) { throw Object.assign(new Error('数据格式不对'), { code: 400 }); }
}

function cookieToken(req) {
  const ck = req.headers['cookie'] || '';
  const m = /(?:^|;\s*)cs_token=([0-9a-f]{64})/.exec(ck);
  return m ? m[1] : '';
}

function setSessionCookie(req, res, token) {
  const https = (req.headers['x-forwarded-proto'] === 'https') || !!req.socket.encrypted;
  const parts = ['cs_token=' + token, 'Path=/', 'HttpOnly', 'SameSite=Lax',
    'Max-Age=' + Math.floor(SESSION_TTL / 1000)];
  if (https) parts.push('Secure');
  const prev = res.getHeader('Set-Cookie');
  const list = Array.isArray(prev) ? prev.slice() : (prev ? [prev] : []);
  list.push(parts.join('; '));
  res.setHeader('Set-Cookie', list);
}

function clearSessionCookie(req, res) {
  const https = (req.headers['x-forwarded-proto'] === 'https') || !!req.socket.encrypted;
  const parts = ['cs_token=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (https) parts.push('Secure');
  const prev = res.getHeader('Set-Cookie');
  const list = Array.isArray(prev) ? prev.slice() : (prev ? [prev] : []);
  list.push(parts.join('; '));
  res.setHeader('Set-Cookie', list);
}

function authUser(req, url) {
  let t = cookieToken(req);
  if (!t) {
    const a = req.headers['authorization'] || '';
    if (a.startsWith('Bearer ')) t = a.slice(7).trim();
  }
  if (!t) t = url.searchParams.get('token') || '';
  if (!t) return null;
  const s = db.sessions.find(x => x.token === t);
  if (!s || s.exp < nowMs()) return null;
  return db.users.find(u => u.id === s.uid) || null;
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.json': 'application/json',
  '.woff2': 'font/woff2', '.mp4': 'video/mp4'
};
const EXT_MIME = {
  pdf: 'application/pdf', zip: 'application/zip', rar: 'application/vnd.rar', '7z': 'application/x-7z-compressed',
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', csv: 'text/csv; charset=utf-8',
  mp3: 'audio/mpeg', m4a: 'audio/mp4', wav: 'audio/wav', mp4: 'video/mp4', mov: 'video/quicktime',
  apk: 'application/vnd.android.package-archive', gif: 'image/gif', png: 'image/png', jpg: 'image/jpeg'
};
function mimeOf(name) {
  const e = (name.split('.').pop() || '').toLowerCase();
  return EXT_MIME[e] || MIME['.' + e] || 'application/octet-stream';
}

/* ==================== 视图 ==================== */
function brief(u) {
  if (!u) return { username: '已注销', nick: '已注销', avatar: 'p1' };
  return { id: u.id, username: u.username, nick: u.nick || u.username, avatar: u.avatar || 'p1' };
}
function msgView(m) {
  const u = db.users.find(x => x.id === m.uid);
  let content = unseal(m.c);
  let meta = null;
  if (m.type === 'file' || m.type === 'image') {
    try { meta = JSON.parse(content); } catch (e) { meta = null; }
  }
  const left = Math.max(0, m.exp - nowMs());
  return {
    id: m.id, seq: m.seq, userId: m.uid,
    username: u ? u.username : '已注销',
    nick: u ? (u.nick || u.username) : '已注销',
    avatar: u ? (u.avatar || 'p1') : 'p1',
    type: m.type, content: meta ? '' : content, file: meta,
    ts: m.ts, exp: m.exp, leftMs: left
  };
}
function onlineIds() {
  const set = new Set();
  for (const c of clients) if (c.uid) set.add(c.uid);
  return set;
}

/* ==================== SSE ==================== */
const clients = new Set();
function broadcast(obj, exceptUid) {
  const line = 'data: ' + JSON.stringify(obj) + '\n\n';
  for (const c of clients) {
    if (exceptUid && c.uid === exceptUid) continue;
    try { c.res.write(line); } catch (e) { /* 忽略 */ }
  }
}
setInterval(() => {
  for (const c of clients) { try { c.res.write(': ping\n\n'); } catch (e) { } }
}, 20000);

function presence() {
  const ids = onlineIds();
  const arr = db.users.map(u => ({ id: u.id, username: u.username, nick: u.nick || u.username, avatar: u.avatar || 'p1', online: ids.has(u.id) }));
  broadcast({ t: 'presence', online: arr.filter(x => x.online).map(x => x.id) });
  return arr;
}

/* ==================== 到期清理 ==================== */
function sweep() {
  const now = nowMs();
  const before = db.msgs.length;
  db.msgs = db.msgs.filter(m => m.exp > now);
  const sb = db.sessions.length;
  db.sessions = db.sessions.filter(s => s.exp > now);
  if (db.msgs.length !== before || db.sessions.length !== sb) {
    save();
    if (db.msgs.length !== before) broadcast({ t: 'purged', removed: before - db.msgs.length });
  }
}
setInterval(sweep, +(process.env.SWEEP_MS || 5 * 60 * 1000));
sweep();

/* ==================== 路由 ==================== */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const path_ = decodeURIComponent(url.pathname);
  const method = req.method;

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');

  try {
    /* ---------- 探活 ---------- */
    if (path_ === '/api/health') {
      return json(res, 200, {
        ok: true, t: nowMs(), retentionDays: RETENTION_DAYS, totpStep: TOTP_STEP,
        users: db.users.length, msgs: db.msgs.length
      });
    }

    /* ---------- 注册（只允许 App 内发起） ---------- */
    if (path_ === '/api/register' && method === 'POST') {
      const b = await readJson(req);
      const username = String(b.username || '').trim();
      const secret = String(b.secret || '').trim();
      if (!/^[\u4e00-\u9fa5A-Za-z0-9_]{2,16}$/.test(username)) return fail(res, 400, '账号名 2-16 位，中文/字母/数字/下划线');
      if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return fail(res, 409, '这个账号名已经被用了');
      const key = b32dec(secret);
      if (key.length < 16) return fail(res, 400, '动态密码密钥无效');
      const code = String(b.code || '');
      const c = checkTotp(key, code);
      if (!c) return fail(res, 400, '动态密码不对，请重试');
      const u = {
        id: uid(), username,
        nick: String(b.nick || username).slice(0, 16),
        avatar: 'p1',
        secret: seal(secret),          // 校验用副本，加密存储
        createdAt: nowMs()
      };
      db.users.push(u);
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions.push({ token, uid: u.id, exp: nowMs() + SESSION_TTL });
      // 注册当下不消耗这个码，方便用户注册后立刻用同一窗口再登一次
      save();
      setSessionCookie(req, res, token);
      presence();
      return json(res, 200, { token, me: brief(u), retentionDays: RETENTION_DAYS, totpStep: TOTP_STEP });
    }

    /* ---------- 登录：账号 + 动态密码 ---------- */
    if (path_ === '/api/login' && method === 'POST') {
      const b = await readJson(req);
      const username = String(b.username || '').trim();
      const code = String(b.code || '').trim();
      const u = db.users.find(x => x.username.toLowerCase() === username.toLowerCase());
      if (!u) return fail(res, 401, '账号或动态密码不对');
      const key = b32dec(unseal(u.secret));
      const c = checkTotp(key, code);
      if (!c) return fail(res, 401, '动态密码不对或已过期');
      if (wasUsed(u.id, c)) {
        const wait = TOTP_STEP - Math.floor(Date.now() / 1000) % TOTP_STEP;
        return fail(res, 401, '这个动态密码刚用过，' + wait + ' 秒后会自动换新码');
      }
      markUsed(u.id, c);
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions.push({ token, uid: u.id, exp: nowMs() + SESSION_TTL });
      db.sessions = db.sessions.filter(s => s.exp > nowMs());
      save();
      setSessionCookie(req, res, token);
      presence();
      return json(res, 200, { token, me: brief(u), retentionDays: RETENTION_DAYS, totpStep: TOTP_STEP });
    }

    /* ---------- 以下都要登录 ---------- */
    const me = authUser(req, url);

    if (path_ === '/api/logout' && method === 'POST') {
      let t = cookieToken(req);
      if (!t) t = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
      db.sessions = db.sessions.filter(s => s.token !== t);
      clearSessionCookie(req, res);
      save();
      if (me) presence();
      return json(res, 200, { ok: true });
    }

    if (path_ === '/api/me' && method === 'GET') {
      if (!me) return fail(res, 401, '请先登录');
      const ids = onlineIds();
      return json(res, 200, {
        me: brief(me),
        members: db.users.map(u => ({ id: u.id, username: u.username, nick: u.nick || u.username, avatar: u.avatar || 'p1', online: ids.has(u.id) })),
        retentionDays: RETENTION_DAYS, totpStep: TOTP_STEP, serverNow: nowMs()
      });
    }

    /* ---------- 改昵称 / 头像 ---------- */
    if (path_ === '/api/profile' && method === 'POST') {
      if (!me) return fail(res, 401, '请先登录');
      const b = await readJson(req);
      if (b.nick != null) {
        const n = String(b.nick).trim().slice(0, 16);
        if (!n) return fail(res, 400, '昵称不能为空');
        me.nick = n;
      }
      if (b.avatar != null) {
        const a = String(b.avatar);
        if (!/^p[1-8]$/.test(a) && !/^\/up\/[\w.-]+$/.test(a)) return fail(res, 400, '头像不合法');
        me.avatar = a;
      }
      save();
      broadcast({ t: 'member', member: brief(me) });
      return json(res, 200, { me: brief(me) });
    }

    /* ---------- 消息列表 ---------- */
    if (path_ === '/api/messages' && method === 'GET') {
      if (!me) return fail(res, 401, '请先登录');
      const limit = Math.min(60, Math.max(1, +(url.searchParams.get('limit') || 30)));
      const before = +(url.searchParams.get('before') || 0);
      let list = db.msgs;
      if (before) list = list.filter(m => m.seq < before);
      const slice = list.slice(-limit);
      return json(res, 200, { messages: slice.map(msgView), hasMore: list.length > limit });
    }

    /* ---------- 发消息 ---------- */
    if (path_ === '/api/messages' && method === 'POST') {
      if (!me) return fail(res, 401, '请先登录');
      const b = await readJson(req);
      const type = ['text', 'image', 'file'].includes(b.type) ? b.type : 'text';
      let content = b.content;
      if (type === 'text') {
        content = String(content || '').trim();
        if (!content) return fail(res, 400, '消息不能为空');
        if (content.length > MAX_TEXT) return fail(res, 400, '消息太长了');
      } else {
        let meta = content;
        if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch (e) { return fail(res, 400, '文件信息不合法'); } }
        const u0 = meta && meta.url;
        const isUp = !!u0 && /^\/up\/[\w.-]+$/.test(u0);
        const isSticker = !!u0 && /^data:image\/svg\+xml/.test(u0) && u0.length < 24000;
        if (!isUp && !isSticker) return fail(res, 400, '文件地址不合法');
        content = JSON.stringify({ url: u0, name: String(meta.name || '文件').slice(0, 120), size: +(meta.size || 0), mime: String(meta.mime || '') });
      }
      const t = nowMs();
      db.seq++;
      const m = {
        id: uid(), seq: db.seq, uid: me.id, type,
        c: seal(content), ts: t, exp: t + RETENTION_DAYS * 24 * 3600 * 1000
      };
      db.msgs.push(m);
      if (db.msgs.length > 5000) db.msgs = db.msgs.slice(-5000);
      save();
      const v = msgView(m);
      broadcast({ t: 'msg', message: v });
      return json(res, 200, { message: v });
    }

    /* ---------- 上传（图片 / 文件） ---------- */
    if (path_ === '/api/upload' && method === 'POST') {
      if (!me) return fail(res, 401, '请先登录');
      const raw = await readBody(req, MAX_FILE);
      if (!raw.length) return fail(res, 400, '空文件');
      const kind = url.searchParams.get('kind') === 'image' ? 'image' : 'file';
      let orig = 'file';
      try { orig = decodeURIComponent(req.headers['x-file-name'] || 'file'); } catch (e) { }
      orig = path.basename(orig).replace(/[\\/:*?"<>|]/g, '_').slice(0, 120) || 'file';
      let ext = (orig.split('.').pop() || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8);
      if (!ext) ext = kind === 'image' ? 'jpg' : 'bin';
      // 图片按文件头验真
      if (kind === 'image') {
        const h = raw.slice(0, 12);
        if (h[0] === 0xFF && h[1] === 0xD8) ext = 'jpg';
        else if (h[0] === 0x89 && h[1] === 0x50) ext = 'png';
        else if (h.slice(0, 3).toString('latin1') === 'GIF') ext = 'gif';
        else if (h.slice(0, 4).toString('latin1') === 'RIFF' && h.slice(8, 12).toString('latin1') === 'WEBP') ext = 'webp';
        else return fail(res, 400, '只支持 JPG / PNG / GIF / WEBP 图片');
      }
      const name = uid() + '_' + Date.now().toString(36) + '.' + ext;
      // 加密后存成二进制，比 base64 省四分之一空间
      const sealedBuf = Buffer.from(seal(raw.toString('base64')), 'utf8');
      await store.putFile(name, sealedBuf);
      // 免费库容量有限，超了按最老的删
      if (MAX_FILES_BYTES > 0) {
        const used = await store.fileUsage();
        if (used.bytes > MAX_FILES_BYTES) {
          const n = await store.pruneFiles(Math.floor(MAX_FILES_BYTES * 0.8));
          console.log('[files] 容量到顶，清掉 ' + n + ' 个旧文件');
        }
      }
      return json(res, 200, { url: '/up/' + name, name: orig, size: raw.length, mime: mimeOf(orig) });
    }

    /* ---------- 取文件 ---------- */
    if (path_.startsWith('/up/') && (method === 'GET' || method === 'HEAD')) {
      const name = path_.slice(4);
      if (name.includes('..') || name.includes('/') || name.includes('\\')) return fail(res, 404, 'Not found');
      const stored = await store.getFile(name);
      if (!stored) return fail(res, 404, '文件已过期或不存在');
      const buf = Buffer.from(unseal(stored.toString('utf8')), 'base64');
      const dl = url.searchParams.get('dl') === '1';
      let fn = name;
      try { fn = url.searchParams.get('name') || name; } catch (e) { }
      const h = {
        'Content-Type': mimeOf(fn),
        'Content-Length': buf.length,
        'Cache-Control': 'private, max-age=3600',
        'Accept-Ranges': 'none'
      };
      if (dl) h['Content-Disposition'] = "attachment; filename*=UTF-8''" + encodeURIComponent(fn);
      res.writeHead(200, h);
      return res.end(method === 'HEAD' ? undefined : buf);
    }

    /* ---------- 销毁倒计时 ---------- */
    if (path_ === '/api/retention' && method === 'GET') {
      if (!me) return fail(res, 401, '请先登录');
      const t = nowMs();
      const expiring = db.msgs.filter(m => m.exp - t <= WARN_MS && m.exp > t);
      const mine = expiring.filter(m => m.uid === me.id);
      const next = db.msgs.reduce((a, m) => Math.min(a, m.exp), Infinity);
      return json(res, 200, {
        days: RETENTION_DAYS,
        total: db.msgs.length,
        expiringAll: expiring.length,
        expiringMine: mine.length,
        firstExpireInMs: expiring.length ? Math.max(0, Math.min(...expiring.map(m => m.exp - t))) : -1,
        nextExpireAt: isFinite(next) ? next : 0,
        exportedAt: me.exportedAt || 0
      });
    }

    /* ---------- 导出 Markdown ---------- */
    if (path_ === '/api/export' && method === 'GET') {
      if (!me) return fail(res, 401, '请先登录');
      const t = nowMs();
      const list = db.msgs.slice();
      const d = new Date();
      const pad = n => String(n).padStart(2, '0');
      const stamp = d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' + pad(d.getHours()) + pad(d.getMinutes());
      let out = '# 尺素 · 聊天记录\n\n';
      out += '> 导出时间：' + d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + '\n';
      out += '> 共 ' + list.length + ' 条 · 消息保留 ' + RETENTION_DAYS + ' 天后自动销毁\n\n---\n\n';
      let lastDay = '';
      for (const m of list) {
        const md = new Date(m.ts);
        const day = md.getFullYear() + '年' + (md.getMonth() + 1) + '月' + md.getDate() + '日';
        if (day !== lastDay) { out += '## ' + day + '\n\n'; lastDay = day; }
        const u = db.users.find(x => x.id === m.uid);
        const who = u ? (u.nick || u.username) : '已注销';
        const hm = pad(md.getHours()) + ':' + pad(md.getMinutes());
        const v = msgView(m);
        if (m.type === 'text') {
          out += '**' + who + '** · ' + hm + '\n\n' + v.content.replace(/\n/g, '\n> ') + '\n\n';
        } else {
          const f = v.file || {};
          if (m.type === 'image') {
            if (/^data:/.test(f.url || '')) out += '**' + who + '** · ' + hm + '\n\n〔小笺：' + (f.name || '表情') + '〕\n\n';
            else out += '**' + who + '** · ' + hm + '\n\n![' + (f.name || '图片') + '](' + f.url + ')\n\n';
          }
          else out += '**' + who + '** · ' + hm + '\n\n📎 [' + (f.name || '文件') + '](' + f.url + '?dl=1&name=' + encodeURIComponent(f.name || 'file') + ')\n\n';
        }
      }
      out += '\n---\n\n_本文件由尺素自动生成。附件链接指向云端，链接过期后失效。_\n';
      me.exportedAt = t;
      save();
      const body = Buffer.from(out, 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Length': body.length,
        'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent('尺素聊天记录-' + stamp + '.md')
      });
      return res.end(body);
    }

    /* ---------- 实时推送 ---------- */
    if (path_ === '/api/stream' && method === 'GET') {
      if (!me) return fail(res, 401, '请先登录');
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });
      res.write('retry: 3000\n\n');
      const c = { res, uid: me.id };
      clients.add(c);
      res.write('data: ' + JSON.stringify({ t: 'hello', online: [...onlineIds()] }) + '\n\n');
      presence();
      const close = () => { clients.delete(c); presence(); };
      req.on('close', close);
      req.on('error', close);
      return;
    }

    /* ---------- 静态资源 ---------- */
    if (method === 'GET' || method === 'HEAD') {
      let rel = path_ === '/' ? '/index.html' : path_;
      if (rel.includes('..')) return fail(res, 404, 'Not found');
      // 先找 public/ 下；没有就找根目录的平铺文件（方便只用手机上传，不用建文件夹）
      let f = path.join(PUB, rel);
      let okRoot = false;
      if (!fs.existsSync(f) || !fs.statSync(f).isFile()) {
        if (FLAT_FILES.has(rel)) {
          f = path.join(ROOT, rel);
          okRoot = true;
        }
      }
      const inside = okRoot ? f.startsWith(ROOT) : f.startsWith(PUB);
      if (!inside || !fs.existsSync(f) || !fs.statSync(f).isFile()) {
        // 未知路径回落到首页，方便直接跟链接打开；
        // 但带扩展名的（.js/.env 之类）一律 404，别把源码和配置当页面返回
        if (!path_.startsWith('/api/') && !path_.startsWith('/.') && !path.extname(path_)) {
          let idx = path.join(PUB, 'index.html');
          if (!fs.existsSync(idx)) idx = path.join(ROOT, 'index.html');
          if (fs.existsSync(idx)) {
            const b = fs.readFileSync(idx);
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-cache' });
            return res.end(b);
          }
        }
        return fail(res, 404, 'Not found');
      }
      const ext = path.extname(f).toLowerCase();
      const b = fs.readFileSync(f);
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Content-Length': b.length,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400'
      });
      return res.end(method === 'HEAD' ? undefined : b);
    }

    return fail(res, 404, 'Not found');
  } catch (e) {
    if (e && e.code === 413) return fail(res, 413, '文件太大（上限 30MB）');
    if (e && e.code === 400) return fail(res, 400, e.message);
    console.error('handler error', req.method, path_, e);
    if (!res.headersSent) return fail(res, 500, '服务器出错了');
    try { res.end(); } catch (_) { }
  }
});

server.headersTimeout = 0;
server.requestTimeout = 0;
server.keepAliveTimeout = 65000;

(async () => {
  try {
    const mode = await store.init({ dataDir: DATA, uploadsDir: UPLOADS, log: console.log });
    const keyFrom = await initMaster();
    db = await store.loadDb({ users: [], msgs: [], sessions: [], seq: 0 });
    console.log('[boot] 存储=' + mode + ' · 主密钥来源=' + keyFrom);
    server.listen(PORT, '0.0.0.0', () => {
      console.log('尺素云端已启动 :' + PORT + '  用户 ' + db.users.length + ' 人 / 消息 ' + db.msgs.length + ' 条');
    });
  } catch (e) {
    console.error('[boot] 启动失败：' + e.message);
    process.exit(1);
  }
})();

/* 平台重新部署前会发 SIGTERM，得把排队中的写入刷下去 */
let closing = false;
['SIGTERM', 'SIGINT'].forEach((sig) => {
  process.on(sig, async () => {
    if (closing) return;
    closing = true;
    console.log('[exit] 收到 ' + sig + '，正在保存…');
    try { server.close(); } catch (e) { }
    await store.close();
    process.exit(0);
  });
});
