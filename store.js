'use strict';
/**
 * 存储层：一个接口，两种后端。
 *
 *   file  —— 本地文件（默认，开发/沙箱用）
 *   pg    —— Postgres（设置了 DATABASE_URL 时启用，云上用）
 *
 * 为什么这么设计：云平台的免费实例没有持久磁盘，重启即清空。
 * 把数据放进托管数据库，才谈得上「聊天记录还在」。
 */

const fs = require('fs');
const path = require('path');

let opts = { dataDir: '', uploadsDir: '', query: null, log: console.log };
let mode = 'file';
let pool = null;

/* 写合并：消息一条条来，不要一条一条打数据库 */
const SAVE_DEBOUNCE = 250;
let timer = null;
let queuedDb = null;
let flushing = null;

function setQuery(fn) {
  opts.query = fn;
  mode = 'pg';
}

async function init(o) {
  opts = Object.assign({}, opts, o);
  if (opts.dataDir) fs.mkdirSync(opts.dataDir, { recursive: true });
  if (opts.uploadsDir) fs.mkdirSync(opts.uploadsDir, { recursive: true });

  if (!opts.query && process.env.DATABASE_URL) {
    let Pool;
    try {
      Pool = require('pg').Pool;
    } catch (e) {
      throw new Error('缺少 pg 依赖：请先 npm install');
    }
    const cs = process.env.DATABASE_URL;
    pool = new Pool({
      connectionString: cs,
      // 托管库（Neon / Supabase / Render）基本都要 SSL，且用的是公共 CA
      ssl: /localhost|127\.0\.0\.1/.test(cs) ? undefined : { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 20000
    });
    pool.on('error', (e) => opts.log('[store] 连接池异常：' + e.message));
    opts.query = (sql, p) => pool.query(sql, p);
    mode = 'pg';
  }

  if (mode === 'pg') {
    await opts.query(`
      create table if not exists chisu_blob (
        k  text primary key,
        v  jsonb not null,
        ts bigint not null
      )`);
    await opts.query(`
      create table if not exists chisu_file (
        name    text primary key,
        data    bytea not null,
        created bigint not null
      )`);
    opts.log('[store] 使用 Postgres 存储');
  } else {
    opts.log('[store] 使用本地文件存储（重启会丢，仅适合开发）');
  }
  return mode;
}

function getMode() { return mode; }

/* ==================== 主数据 ==================== */

async function loadDb(fallback) {
  if (mode === 'pg') {
    const r = await opts.query("select v from chisu_blob where k = 'db'");
    if (r.rows && r.rows.length) {
      const v = r.rows[0].v;
      return Object.assign({}, fallback, typeof v === 'string' ? JSON.parse(v) : v);
    }
    return fallback;
  }
  const f = path.join(opts.dataDir, 'db.json');
  try {
    if (fs.existsSync(f)) return Object.assign({}, fallback, JSON.parse(fs.readFileSync(f, 'utf8')));
  } catch (e) { opts.log('[store] db.json 读取失败：' + e.message); }
  return fallback;
}

/** 排队写。高频调用只会合并成一次落盘。 */
function saveDb(db) {
  queuedDb = db;
  schedule();
}

function schedule() {
  if (timer || flushing) return;
  timer = setTimeout(async () => {
    timer = null;
    flushing = flush().catch((e) => opts.log('[store] 保存失败：' + e.message));
    try { await flushing; } catch (e) { }
    flushing = null;
    // 上一轮期间又来了新数据，接着写
    if (queuedDb) schedule();
  }, SAVE_DEBOUNCE);
}

async function flush() {
  const db = queuedDb;
  if (!db) return;
  queuedDb = null;
  const json = JSON.stringify(db);
  if (mode === 'pg') {
    await opts.query(
      "insert into chisu_blob(k, v, ts) values('db', $1::jsonb, $2) " +
      "on conflict (k) do update set v = excluded.v, ts = excluded.ts",
      [json, Date.now()]
    );
  } else {
    const f = path.join(opts.dataDir, 'db.json');
    fs.writeFileSync(f + '.tmp', json);
    fs.renameSync(f + '.tmp', f);
  }
}

/** 进程退出前把没写完的刷掉 */
async function close() {
  if (timer) { clearTimeout(timer); timer = null; }
  try { await flush(); } catch (e) { }
  if (pool) { try { await pool.end(); } catch (e) { } }
}

/* ==================== 密钥（必须跨重启保留） ==================== */

/**
 * master.key 丢了，历史消息就永远解不开。
 * 所以它也得进数据库，不能只躺在磁盘上。
 */
async function loadSecret(name) {
  if (mode === 'pg') {
    const r = await opts.query('select v from chisu_blob where k = $1', ['secret:' + name]);
    if (r.rows && r.rows.length) {
      const v = r.rows[0].v;
      return typeof v === 'string' ? v : (v && v.s) || null;
    }
    return null;
  }
  const f = path.join(opts.dataDir, name);
  try { if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim(); } catch (e) { }
  return null;
}

async function saveSecret(name, val) {
  if (mode === 'pg') {
    await opts.query(
      "insert into chisu_blob(k, v, ts) values($1, $2::jsonb, $3) " +
      "on conflict (k) do update set v = excluded.v, ts = excluded.ts",
      ['secret:' + name, JSON.stringify({ s: val }), Date.now()]
    );
    return;
  }
  fs.writeFileSync(path.join(opts.dataDir, name), val, { mode: 0o600 });
}

/* ==================== 上传的文件 ==================== */

async function putFile(name, buf) {
  if (mode === 'pg') {
    await opts.query(
      'insert into chisu_file(name, data, created) values($1, $2, $3) ' +
      'on conflict (name) do update set data = excluded.data',
      [name, buf, Date.now()]
    );
    return;
  }
  fs.writeFileSync(path.join(opts.uploadsDir, name), buf, { mode: 0o600 });
}

async function getFile(name) {
  if (mode === 'pg') {
    const r = await opts.query('select data from chisu_file where name = $1', [name]);
    if (!r.rows || !r.rows.length) return null;
    return Buffer.from(r.rows[0].data);
  }
  const f = path.join(opts.uploadsDir, name);
  try { if (fs.existsSync(f)) return fs.readFileSync(f); } catch (e) { }
  return null;
}

async function fileUsage() {
  if (mode === 'pg') {
    const r = await opts.query('select count(*)::int as n, coalesce(sum(length(data)),0)::bigint as b from chisu_file');
    const row = (r.rows && r.rows[0]) || { n: 0, b: 0 };
    return { count: row.n || 0, bytes: Number(row.b) || 0 };
  }
  let count = 0, bytes = 0;
  try {
    for (const f of fs.readdirSync(opts.uploadsDir)) {
      count++;
      try { bytes += fs.statSync(path.join(opts.uploadsDir, f)).size; } catch (e) { }
    }
  } catch (e) { }
  return { count, bytes };
}

/** 免费库只有 0.5GB，图片必须设上限：超了按最老的删，直到降回八成 */
async function pruneFiles(maxBytes) {
  let used = (await fileUsage()).bytes;
  if (used <= maxBytes) return 0;
  let killed = 0;
  for (let round = 0; round < 30 && used > maxBytes; round++) {
    if (mode === 'pg') {
      const r = await opts.query(
        'select name, length(data) as b from chisu_file order by created asc limit 100'
      );
      if (!r.rows || !r.rows.length) break;
      for (const row of r.rows) {
        if (used <= maxBytes) break;
        await opts.query('delete from chisu_file where name = $1', [row.name]);
        used -= Number(row.b) || 0;
        killed++;
      }
    } else {
      let list;
      try {
        list = fs.readdirSync(opts.uploadsDir).map((n) => {
          const st = fs.statSync(path.join(opts.uploadsDir, n));
          return { n, t: st.mtimeMs, b: st.size };
        }).sort((a, b) => a.t - b.t);
      } catch (e) { break; }
      if (!list.length) break;
      for (const it of list) {
        if (used <= maxBytes) break;
        try { fs.unlinkSync(path.join(opts.uploadsDir, it.n)); } catch (e) { }
        used -= it.b;
        killed++;
      }
    }
  }
  return killed;
}

module.exports = {
  init, getMode, setQuery, loadDb, saveDb, flush, close,
  loadSecret, saveSecret,
  putFile, getFile, fileUsage, pruneFiles
};
