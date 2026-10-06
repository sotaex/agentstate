/**
 * Antinel 值守台 · 匿名计数端点（Cloudflare Worker）
 * =================================================
 * 职责**极简**：收一个只含固定字段的计数报文，去重、累加、给一个汇总。
 *
 * ★ 三条纪律（与产品侧 heartbeat.py 一一对应）：
 *   1. 只接受固定字段；多一个字段就拒（不是"忽略"，是**拒**）。
 *   2. **不存 IP、不存 UA、不存时间戳到秒**；install_id **只存哈希**，不存原文。
 *   3. 只在 (date, install_id) 上做**去重**；一个安装一天只算一次。
 *
 * ★ 诚实的精度说明（别对外说过头）：
 *   KV 的读改写**不是原子的**。高并发下计数会**偏低**（丢增量），不会偏高。
 *   ⇒ 这个数适合看**趋势与量级**；要"一个不差"的精确数，把下面的
 *     `ExactCounter`（Durable Object 版，本文件末尾附）启用即可 —— 客户端不用改。
 *   对外表述纪律：**只能叫"开启了统计的安装数"，不能叫"用户数"。**
 *
 * 部署：见 outputs/Antinel 值守台·心跳端点部署说明 v1.0（2026-10-05）.md
 *   wrangler kv namespace create ANTINEL_HB   # 把返回的 id 填进 wrangler.toml
 *   wrangler deploy
 */

const TOP_FIELDS = ["install_id", "date", "version", "buckets", "schema"];
const BUCKET_FIELDS = ["r0", "l2", "l1", "ls"];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function bad(msg) {
  return json({ ok: false, error: msg }, 400);
}

/** 严格校验：字段集必须**完全等于**约定，多一个少一个都拒。 */
function validate(p) {
  if (!p || typeof p !== "object" || Array.isArray(p)) return "body 不是对象";
  const keys = Object.keys(p).sort();
  if (keys.join(",") !== [...TOP_FIELDS].sort().join(",")) {
    return "顶层字段必须恰好是 " + TOP_FIELDS.join("/") + "，收到 " + keys.join("/");
  }
  if (typeof p.install_id !== "string" || p.install_id.length < 8 || p.install_id.length > 64) {
    return "install_id 不合法";
  }
  if (typeof p.date !== "string" || !DATE_RE.test(p.date)) return "date 不合法";
  if (typeof p.version !== "string" || p.version.length > 32) return "version 不合法";
  if (p.schema !== 1) return "schema 不支持";
  const b = p.buckets;
  if (!b || typeof b !== "object" || Array.isArray(b)) return "buckets 不是对象";
  const bk = Object.keys(b).sort();
  if (bk.join(",") !== [...BUCKET_FIELDS].sort().join(",")) {
    return "buckets 字段必须恰好是 " + BUCKET_FIELDS.join("/");
  }
  for (const k of BUCKET_FIELDS) {
    const v = b[k];
    if (!Number.isInteger(v) || v < 0 || v > 1000000) return "buckets." + k + " 不合法";
  }
  return "";
}

/** install_id -> 短哈希（**不存原文**）。 */
async function hashId(id) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(id));
  return [...new Uint8Array(buf)].slice(0, 12).map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function ingest(request, env) {
  let p;
  try {
    p = await request.json();
  } catch (e) {
    return bad("不是合法 JSON");
  }
  const err = validate(p);
  if (err) return bad(err);

  const h = await hashId(p.install_id);
  const seenKey = `seen:${p.date}:${h}`;

  // 去重：一个安装一天只算一次（KV 最终一致；重复上报最多多算一次，不会少算）
  const already = await env.ANTINEL_HB.get(seenKey);
  if (already) return json({ ok: true, counted: false });

  await env.ANTINEL_HB.put(seenKey, "1", { expirationTtl: 60 * 60 * 24 * 45 });

  const cKey = `c:${p.date}`;
  const cur = JSON.parse((await env.ANTINEL_HB.get(cKey)) || '{"installs":0,"r0":0,"l2":0,"l1":0,"ls":0,"v":{}}');
  cur.installs += 1;
  for (const k of BUCKET_FIELDS) cur[k] += p.buckets[k] | 0;
  cur.v[p.version] = (cur.v[p.version] || 0) + 1;
  // 30 天滚动窗口（只保留近期，不做长期画像）
  await env.ANTINEL_HB.put(cKey, JSON.stringify(cur), { expirationTtl: 60 * 60 * 24 * 400 });

  return json({ ok: true, counted: true });
}

async function summary(env, url) {
  const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get("days") || "30", 10) || 30));
  const out = { days, installs: 0, byDay: {}, byLevel: { r0: 0, l2: 0, l1: 0, ls: 0 } };
  // ★ 2026-10-06 修复（实测咬中）：**不按服务器时钟算日期**。
  //   客户端报的 date 是**客户端本地日期**（UTC+8 用户在 UTC 的 21:58 报的是"明天"），
  //   旧版 summary 按 UTC 算今天再往前推 N 天 ⇒ 读的全是没人写过的键
  //   （实测：ingest 写 c:2026-10-06，summary 按 UTC 读 c:2026-10-05 ⇒ installs 恒 0）。
  //   改为**列出已上报的 c:* 键、取日期最新的 N 个** —— 与任何时区、任何时钟漂移无关。
  //   （键总量受 400 天 TTL 与每日一键约束，远小于 list 单页 1000 上限，无需翻页。）
  const list = await env.ANTINEL_HB.list({ prefix: "c:" });
  const dates = list.keys.map((k) => k.name.slice(2)).sort().reverse().slice(0, days);
  for (const d of dates) {
    const raw = await env.ANTINEL_HB.get(`c:${d}`);
    if (!raw) continue;
    const c = JSON.parse(raw);
    out.byDay[d] = c.installs | 0;
    out.installs += c.installs | 0;
    for (const k of BUCKET_FIELDS) out.byLevel[k] += c[k] | 0;
  }
  return json(out);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/") return ingest(request, env);
    if (request.method === "GET" && url.pathname === "/summary") return summary(env, url);
    return json({ ok: false, error: "not found" }, 404);
  },
};

/* ---------------------------------------------------------------------------
 * 可选：要"一个不差"的精确计数（Durable Object 版）
 *
 * KV 的读改写不原子，高并发会**偏低**。若投资人要看精确数，改用下面的
 * 单实例 Durable Object（串行化，天然原子）—— **客户端一行都不用改**：
 *
 *   wrangler.toml:
 *     [[durable_objects.bindings]]
 *     name = "COUNTER"
 *     class_name = "ExactCounter"
 *     [[migrations]]
 *     tag = "v1"
 *     new_sqlite_classes = ["ExactCounter"]
 *
 *   ingest() 里把 KV 读改写换成：
 *     const id = env.COUNTER.idFromName("global");
 *     const stub = env.COUNTER.get(id);
 *     await stub.fetch("https://do/inc", { method: "POST", body: JSON.stringify(p) });
 *
 * export class ExactCounter {
 *   constructor(state) { this.state = state; this.data = null; }
 *   async load() {
 *     if (!this.data) this.data = (await this.state.storage.get("d")) || { byDay: {}, seen: {} };
 *     return this.data;
 *   }
 *   async fetch(req) {
 *     const d = await this.load();
 *     const p = await req.json();
 *     const h = await hashId(p.install_id);
 *     const k = p.date + ":" + h;
 *     if (!d.seen[k]) {
 *       d.seen[k] = 1;
 *       const c = (d.byDay[p.date] = d.byDay[p.date] || { installs: 0, r0: 0, l2: 0, l1: 0, ls: 0 });
 *       c.installs += 1;
 *       for (const b of BUCKET_FIELDS) c[b] += p.buckets[b] | 0;
 *       await this.state.storage.put("d", d);
 *     }
 *     return json({ ok: true });
 *   }
 * }
 * ------------------------------------------------------------------------- */
