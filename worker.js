// ============================================================
//  فاحص الروابط — Cloudflare Worker واحد (واجهة + فحص + سجل)
//  KV binding: LOGS      Secrets: ADMIN_KEY (مطلوب), TEAM_KEY (اختياري)
// ============================================================

const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 10000;
const LOG_TTL = 60 * 60 * 24 * 90; // حذف السجل تلقائياً بعد 90 يوماً
const UA = "Mozilla/5.0 (compatible; TeamLinkChecker/1.0)";

export default {
  async fetch(req, env, ctx) {
    const { pathname: p } = new URL(req.url);
    try {
      if (req.method === "GET" && p === "/") return page(PAGE);
      if (req.method === "GET" && p === "/admin") return page(ADMIN);
      if (req.method === "GET" && p === "/api/config") return json({ needKey: !!env.TEAM_KEY });
      if (req.method === "POST" && p === "/api/check") return handleCheck(req, env, ctx);
      if (req.method === "GET" && p === "/api/logs") return handleLogs(req, env);
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: "internal" }, 500);
    }
  },
};

/* ---------------- الفحص ---------------- */

async function handleCheck(req, env, ctx) {
  let body;
  try { body = await req.json(); } catch { return json({ error: "bad_request" }, 400); }

  if (env.TEAM_KEY && !safeEqual(String(body.key || ""), env.TEAM_KEY)) {
    return json({ error: "unauthorized" }, 401);
  }
  const name = String(body.name || "").trim().slice(0, 30);
  if (!name) return json({ error: "name_required" }, 400);

  const start = normalize(body.url);
  let result;
  if (!start) {
    result = { status: "invalid", code: 0, ms: 0, finalUrl: "", chain: [] };
  } else {
    result = await checkUrl(start);
  }

  if (env.LOGS) ctx.waitUntil(writeLog(env, name, start, String(body.url || ""), result));
  return json(result);
}

function normalize(raw) {
  raw = String(raw || "").trim().slice(0, 2000);
  if (!raw) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "https://" + raw;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  return u;
}

function isPrivateHost(h) {
  h = h.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h.startsWith("[")) return true; // عناوين IPv6 المباشرة غير مدعومة
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [+m[1], +m[2]];
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
         (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
}

async function checkUrl(startUrl) {
  const t0 = Date.now();
  const chain = [];
  const seen = new Set();
  let cur = startUrl;

  const finish = (status, code = 0) => ({
    status,
    code,
    ms: Date.now() - t0,
    finalUrl: chain.length ? chain[chain.length - 1].url : startUrl.href,
    chain,
  });

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (isPrivateHost(cur.hostname)) return finish("blocked_target");
    if (seen.has(cur.href)) return finish("redirect_loop");
    seen.add(cur.href);

    let r;
    try {
      r = await fetch(cur.href, {
        method: "GET",
        redirect: "manual",
        headers: { "User-Agent": UA, Accept: "text/html,*/*;q=0.8" },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e) {
      chain.push({ url: cur.href, code: 0 });
      return finish(await classifyError(e, cur.hostname));
    }
    try { r.body && r.body.cancel(); } catch {}
    chain.push({ url: cur.href, code: r.status });

    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers.get("location");
      if (!loc) return finish("bad_redirect", r.status);
      try { cur = new URL(loc, cur.href); } catch { return finish("bad_redirect", r.status); }
      if (cur.protocol !== "http:" && cur.protocol !== "https:") return finish("bad_redirect", r.status);
      continue;
    }
    return finish(classify(r.status, chain.length > 1), r.status);
  }
  return finish("redirect_loop");
}

function classify(code, redirected) {
  if (code >= 200 && code < 300) return redirected ? "ok_redirect" : "ok";
  if (code === 404 || code === 410) return "page_missing";
  if (code === 401 || code === 403 || code === 429) return "forbidden";
  if (code >= 500) return "server_error";
  if (code >= 400) return "client_error";
  return "other";
}

async function classifyError(e, host) {
  if (e && (e.name === "TimeoutError" || e.name === "AbortError")) return "timeout";
  if (await dnsMissing(host)) return "domain_not_found";
  if (/ssl|tls|cert|handshake/i.test(String(e && e.message))) return "ssl_error";
  return "unreachable";
}

// الـ Worker لا يملك فحص DNS مباشراً، فنسأل DoH من Cloudflare. الرمز 3 = النطاق غير موجود.
async function dnsMissing(host) {
  try {
    const r = await fetch(
      "https://cloudflare-dns.com/dns-query?type=A&name=" + encodeURIComponent(host),
      { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) }
    );
    const j = await r.json();
    return j.Status === 3;
  } catch { return false; }
}

/* ---------------- السجل ---------------- */

// نحذف الاستعلام (?token=...) والجزء (#...) قبل الحفظ
function clean(href) {
  try {
    const u = new URL(href);
    return (u.origin + u.pathname + (u.search ? "?…" : "")).slice(0, 220);
  } catch { return ""; }
}

async function writeLog(env, name, startUrl, rawInput, res) {
  try {
    const ts = Date.now();
    const key = "log:" + String(9999999999999 - ts).padStart(13, "0") + ":" + crypto.randomUUID().slice(0, 6);
    const meta = {
      n: name,
      t: ts,
      u: startUrl ? clean(startUrl.href) : "(غير صالح)",
      f: clean(res.finalUrl),
      s: res.status,
      c: res.code,
      ms: res.ms,
      h: res.chain.map((x) => x.code).join(">"),
    };
    const value = { ...meta, chain: res.chain.map((x) => ({ url: clean(x.url), code: x.code })) };
    await env.LOGS.put(key, JSON.stringify(value), { expirationTtl: LOG_TTL, metadata: meta });
  } catch { /* فشل التسجيل لا يمنع ظهور النتيجة */ }
}

async function handleLogs(req, env) {
  const k = req.headers.get("x-admin-key") || "";
  if (!env.ADMIN_KEY || !safeEqual(k, env.ADMIN_KEY)) return json({ error: "unauthorized" }, 401);
  if (!env.LOGS) return json({ rows: [], cursor: null });
  const cursor = new URL(req.url).searchParams.get("cursor") || undefined;
  const list = await env.LOGS.list({ prefix: "log:", limit: 1000, cursor });
  return json({
    rows: list.keys.map((x) => x.metadata).filter(Boolean),
    cursor: list.list_complete ? null : list.cursor,
  });
}

/* ---------------- أدوات ---------------- */

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function page(html) {
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-robots-tag": "noindex",
      "content-security-policy":
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
    },
  });
}

/* ---------------- الواجهة ---------------- */

const CSS = String.raw`
:root{--bg:#f3f5f7;--surface:#fff;--ink:#16202a;--muted:#5d6b78;--line:#dde3e8;--accent:#1d4ed8;--accent-ink:#fff;
--good:#15803d;--warn:#b45309;--bad:#b91c1c;--good-bg:#e7f5ec;--warn-bg:#fdf1dc;--bad-bg:#fce9e7}
@media (prefers-color-scheme:dark){:root{--bg:#10161c;--surface:#18212a;--ink:#e6edf3;--muted:#93a1ae;--line:#2a3541;
--accent:#6ea0ff;--accent-ink:#0a1220;--good:#6fdc98;--warn:#f2b45a;--bad:#ff8f87;--good-bg:#12301f;--warn-bg:#35280d;--bad-bg:#3b1a17}}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.7 "Segoe UI",Tahoma,"Noto Naskh Arabic",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:28px 18px 60px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;flex-wrap:wrap}
h1{font-size:1.5rem;margin:0;font-weight:700}
.who{font-size:.9rem;color:var(--muted)}
button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--ink);padding:8px 16px}
button.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent);font-weight:600}
button:disabled{opacity:.55;cursor:default}
button.link{border:0;background:none;color:var(--accent);padding:0 4px;text-decoration:underline}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
textarea,input[type=text],input[type=password]{width:100%;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
textarea{min-height:150px;direction:ltr;text-align:left;resize:vertical;font-family:ui-monospace,Consolas,monospace;font-size:.92rem}
.bar{display:flex;gap:10px;align-items:center;margin:12px 0;flex-wrap:wrap}
.bar .grow{flex:1;color:var(--muted);font-size:.9rem}
.sum{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 10px}
.chip{padding:3px 12px;border-radius:99px;font-size:.88rem;font-weight:600}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.chip.good{background:var(--good-bg)}.chip.warn{background:var(--warn-bg)}.chip.bad{background:var(--bad-bg)}
.row{background:var(--surface);border:1px solid var(--line);border-inline-start:5px solid var(--line);border-radius:8px;margin-bottom:8px}
.row.good{border-inline-start-color:var(--good)}.row.warn{border-inline-start-color:var(--warn)}.row.bad{border-inline-start-color:var(--bad)}
.row summary{list-style:none;cursor:pointer;padding:10px 14px;display:grid;grid-template-columns:1fr auto;gap:2px 12px}
.row summary::-webkit-details-marker{display:none}
.row .st{font-weight:700}
.row .url{grid-column:1/-1;direction:ltr;text-align:left;color:var(--muted);font-size:.86rem;overflow-wrap:anywhere}
.row .meta{color:var(--muted);font-size:.86rem;text-align:left}
.row .steps{margin:0;padding:4px 14px 12px;list-style:none;direction:ltr;text-align:left;font-size:.85rem;border-top:1px solid var(--line)}
.row .steps li{padding:3px 0;overflow-wrap:anywhere}
.row .steps b{display:inline-block;min-width:3.2em}
.note{margin-top:28px;font-size:.85rem;color:var(--muted)}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--surface);color:var(--ink);padding:24px;width:min(380px,92vw)}
dialog::backdrop{background:rgba(0,0,0,.5)}
dialog h2{margin:0 0 6px;font-size:1.15rem}
dialog p{margin:0 0 14px;color:var(--muted);font-size:.92rem}
dialog label{display:block;margin:10px 0 4px;font-size:.9rem}
.err{color:var(--bad);font-size:.88rem;min-height:1.3em;margin:8px 0 0}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);font-size:.88rem}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
th{background:var(--bg);font-weight:600}
td.l{direction:ltr;text-align:left;overflow-wrap:anywhere}
.scroll{overflow-x:auto}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:12px 0}
.stats{display:flex;gap:22px;flex-wrap:wrap;margin:16px 0}
.stats div{font-size:.88rem;color:var(--muted)}
.stats strong{display:block;font-size:1.5rem;color:var(--ink)}
`;

const LABELS = String.raw`
const LABELS={
 ok:["✅","يعمل","good"],
 ok_redirect:["↪️","يعمل بعد تحويل","good"],
 page_missing:["⚠️","الموقع موجود لكن الصفحة مفقودة","warn"],
 forbidden:["⛔","ممنوع أو محجوب (قد يعمل في المتصفح)","warn"],
 client_error:["⚠️","خطأ في الطلب","warn"],
 other:["❔","استجابة غير معتادة","warn"],
 server_error:["🔥","خطأ في الخادم","bad"],
 redirect_loop:["🔁","حلقة تحويل أو تحويلات كثيرة","bad"],
 timeout:["⏱️","انتهت المهلة","bad"],
 domain_not_found:["❌","النطاق غير موجود","bad"],
 ssl_error:["🔒","مشكلة في شهادة SSL","bad"],
 unreachable:["🚫","تعذّر الاتصال بالخادم","bad"],
 bad_redirect:["↩️","تحويل معطوب","bad"],
 invalid:["❓","رابط غير صالح","bad"],
 blocked_target:["🛡️","وجهة غير مسموحة","bad"]
};
function csvCell(v){v=String(v==null?"":v);if(/^[=+\-@]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"';}
function downloadCsv(rows,file){
  const text="\ufeff"+rows.map(r=>r.map(csvCell).join(",")).join("\r\n");
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([text],{type:"text/csv;charset=utf-8"}));
  a.download=file;document.body.appendChild(a);a.click();a.remove();
}
`;

const PAGE = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>فاحص الروابط</title>
<style>${CSS}</style>
</head>
<body>
<main>
  <header>
    <h1>فاحص الروابط</h1>
    <div class="who">المستخدم: <b id="who">—</b> <button class="link" id="change" type="button">تغيير</button></div>
  </header>

  <label for="urls" class="who">ألصق الروابط، رابطاً في كل سطر</label>
  <textarea id="urls" spellcheck="false" placeholder="https://example.com&#10;example.org/page"></textarea>
  <div class="bar">
    <button class="primary" id="go" type="button">افحص الروابط</button>
    <button id="csv" type="button" hidden>تصدير CSV</button>
    <span class="grow" id="progress" aria-live="polite"></span>
  </div>

  <div class="sum" id="sum"></div>
  <div id="results"></div>

</main>

<dialog id="dlg">
  <form method="dialog" id="form">
    <h2>اكتب اسمك</h2>
    <label for="nm">الاسم</label>
    <input type="text" id="nm" maxlength="30" autocomplete="name">
    <div id="keywrap" hidden>
      <label for="tk">رمز الفريق</label>
      <input type="password" id="tk" autocomplete="off">
    </div>
    <div class="err" id="err"></div>
    <div class="bar"><button class="primary" type="submit">حفظ</button></div>
  </form>
</dialog>

<script>
${LABELS}
const $=s=>document.querySelector(s);
let name=localStorage.getItem("lc_name")||"", key=localStorage.getItem("lc_key")||"", needKey=false;
const results=[];

function showWho(){ $("#who").textContent=name||"—"; }
function openDlg(msg){
  $("#nm").value=name; $("#tk").value=key;
  $("#keywrap").hidden=!needKey; $("#err").textContent=msg||"";
  if(!$("#dlg").open) $("#dlg").showModal();
}
$("#dlg").addEventListener("cancel",e=>{ if(!name) e.preventDefault(); });
$("#form").addEventListener("submit",e=>{
  const n=$("#nm").value.trim(), k=$("#tk").value.trim();
  if(!n || (needKey && !k)){ e.preventDefault(); $("#err").textContent=needKey?"اكتب الاسم ورمز الفريق.":"اكتب اسمك للمتابعة."; return; }
  name=n; key=k; localStorage.setItem("lc_name",n); localStorage.setItem("lc_key",k); showWho();
});
$("#change").onclick=()=>openDlg();

function el(tag,cls,text){ const x=document.createElement(tag); if(cls)x.className=cls; if(text!=null)x.textContent=text; return x; }

function makeRow(url){
  const d=el("details","row"); const s=el("summary");
  s.append(el("span","st","⏳ جارٍ الفحص…"), el("span","meta",""), el("span","url",url));
  d.append(s); $("#results").append(d); return d;
}
function fillRow(d,r){
  const L=LABELS[r.status]||LABELS.other;
  d.classList.add(L[2]);
  const s=d.querySelector("summary");
  s.querySelector(".st").textContent=L[0]+" "+L[1];
  s.querySelector(".st").className="st "+L[2];
  s.querySelector(".meta").textContent=(r.code?r.code+" · ":"")+r.ms+"ms"+(r.chain.length>1?" · "+(r.chain.length-1)+" تحويل":"");
  if(r.chain.length>1 || (r.finalUrl && r.finalUrl!==s.querySelector(".url").textContent)){
    const ul=el("ul","steps");
    r.chain.forEach(c=>{ const li=el("li"); li.append(el("b","",c.code||"—"), document.createTextNode(c.url)); ul.append(li); });
    d.append(ul);
  }
}

function renderSum(){
  const t={good:0,warn:0,bad:0}; results.forEach(r=>t[(LABELS[r.status]||LABELS.other)[2]]++);
  const box=$("#sum"); box.replaceChildren();
  [["good","يعمل"],["warn","يحتاج مراجعة"],["bad","لا يعمل"]].forEach(([c,l])=>{ if(t[c]) box.append(el("span","chip "+c,t[c]+" "+l)); });
}

async function checkOne(url){
  const res=await fetch("/api/check",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({url,name,key})});
  if(res.status===401){ const e=new Error("auth"); e.auth=true; throw e; }
  if(!res.ok) throw new Error("http "+res.status);
  return res.json();
}

async function run(){
  if(!name){ openDlg(); return; }
  const list=[...new Set($("#urls").value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean))].slice(0,500);
  if(!list.length){ $("#progress").textContent="ألصق رابطاً واحداً على الأقل."; return; }
  $("#go").disabled=true; $("#csv").hidden=true; $("#results").replaceChildren(); $("#sum").replaceChildren(); results.length=0;
  const rows=list.map(makeRow); let next=0, done=0, stop=false;
  const tick=()=>{ $("#progress").textContent="تم فحص "+done+" من "+list.length; };
  tick();
  async function worker(){
    while(!stop){
      const i=next++; if(i>=list.length) return;
      try{
        const r=await checkOne(list[i]); r.input=list[i]; results.push(r); fillRow(rows[i],r);
      }catch(e){
        if(e.auth){ stop=true; openDlg("رمز الفريق غير صحيح."); return; }
        const r={status:"unreachable",code:0,ms:0,finalUrl:"",chain:[],input:list[i]}; results.push(r); fillRow(rows[i],r);
      }
      done++; tick(); renderSum();
    }
  }
  await Promise.all([worker(),worker(),worker(),worker()]);
  $("#go").disabled=false; $("#csv").hidden=!results.length;
  if(stop) $("#progress").textContent="توقف الفحص: تحقق من رمز الفريق."; else $("#progress").textContent="اكتمل الفحص.";
}
$("#go").onclick=run;
$("#csv").onclick=()=>{
  const head=["الرابط","الحالة","الكود","الرابط النهائي","عدد التحويلات","الزمن (ms)"];
  downloadCsv([head,...results.map(r=>[r.input,(LABELS[r.status]||LABELS.other)[1],r.code,r.finalUrl,Math.max(0,r.chain.length-1),r.ms])],"link-check.csv");
};

showWho();
fetch("/api/config").then(r=>r.json()).then(c=>{ needKey=c.needKey; if(!name||(needKey&&!key)) openDlg(); }).catch(()=>{ if(!name) openDlg(); });
</script>
</body>
</html>`;

const ADMIN = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>سجل الفحوصات</title>
<style>${CSS}</style>
</head>
<body>
<main>
  <header><h1>سجل الفحوصات</h1><a class="who" href="/">العودة إلى الفاحص</a></header>

  <div id="login">
    <label for="ak" class="who">مفتاح المسؤول</label>
    <div class="bar"><input type="password" id="ak" autocomplete="off" style="max-width:320px"><button class="primary" id="enter" type="button">دخول</button></div>
    <div class="err" id="err"></div>
  </div>

  <div id="panel" hidden>
    <div class="stats" id="stats"></div>
    <div class="filters">
      <input type="text" id="fq" placeholder="بحث في الرابط">
      <select id="fn" aria-label="الاسم"><option value="">كل الأسماء</option></select>
      <select id="fs" aria-label="النتيجة"><option value="">كل النتائج</option><option value="good">يعمل</option><option value="warn">يحتاج مراجعة</option><option value="bad">لا يعمل</option></select>
    </div>
    <div class="bar">
      <button id="more" type="button" hidden>تحميل المزيد</button>
      <button id="csv" type="button">تصدير CSV</button>
      <span class="grow" id="count"></span>
    </div>
    <div class="scroll"><table>
      <thead><tr><th>الوقت</th><th>الاسم</th><th>الرابط</th><th>النتيجة</th><th>الكود</th><th>التحويلات</th><th>ms</th></tr></thead>
      <tbody id="body"></tbody>
    </table></div>
  </div>
</main>

<script>
${LABELS}
const $=s=>document.querySelector(s);
let all=[], cursor=null, akey=sessionStorage.getItem("lc_admin")||"";
function el(tag,cls,text){ const x=document.createElement(tag); if(cls)x.className=cls; if(text!=null)x.textContent=text; return x; }
const cat=r=>(LABELS[r.s]||LABELS.other)[2];

async function load(more){
  const res=await fetch("/api/logs"+(more&&cursor?"?cursor="+encodeURIComponent(cursor):""),{headers:{"x-admin-key":akey}});
  if(res.status===401){ sessionStorage.removeItem("lc_admin"); $("#login").hidden=false; $("#panel").hidden=true; $("#err").textContent="المفتاح غير صحيح."; return; }
  const j=await res.json();
  all=more?all.concat(j.rows):j.rows; cursor=j.cursor;
  $("#login").hidden=true; $("#panel").hidden=false; $("#more").hidden=!cursor;
  const names=[...new Set(all.map(r=>r.n))].sort(), cur=$("#fn").value;
  $("#fn").replaceChildren(new Option("كل الأسماء","")); names.forEach(n=>$("#fn").append(new Option(n,n))); $("#fn").value=cur;
  draw();
}
function filtered(){
  const q=$("#fq").value.trim().toLowerCase(), n=$("#fn").value, s=$("#fs").value;
  return all.filter(r=>(!q||(r.u+" "+r.f).toLowerCase().includes(q))&&(!n||r.n===n)&&(!s||cat(r)===s));
}
function draw(){
  const rows=filtered(), body=$("#body"); body.replaceChildren();
  rows.slice(0,500).forEach(r=>{
    const L=LABELS[r.s]||LABELS.other, tr=el("tr");
    tr.append(el("td","",new Date(r.t).toLocaleString("ar-EG")), el("td","",r.n), el("td","l",r.u), el("td",L[2],L[0]+" "+L[1]), el("td","",r.c||"—"), el("td","l",r.h||"—"), el("td","",r.ms));
    body.append(tr);
  });
  const bad=all.filter(r=>cat(r)==="bad").length, pct=all.length?Math.round(bad/all.length*100):0;
  const st=$("#stats"); st.replaceChildren();
  [[all.length,"فحصاً محمّلاً"],[pct+"%","روابط لا تعمل"],[new Set(all.map(r=>r.n)).size,"مستخدمين"]].forEach(([v,l])=>{ const d=el("div"); d.append(el("strong","",v),document.createTextNode(l)); st.append(d); });
  $("#count").textContent="المعروض: "+Math.min(rows.length,500)+" من "+rows.length;
}
["fq","fn","fs"].forEach(id=>$("#"+id).addEventListener("input",draw));
$("#more").onclick=()=>load(true);
$("#enter").onclick=()=>{ akey=$("#ak").value.trim(); sessionStorage.setItem("lc_admin",akey); $("#err").textContent=""; load(false); };
$("#ak").addEventListener("keydown",e=>{ if(e.key==="Enter") $("#enter").click(); });
$("#csv").onclick=()=>downloadCsv([["الوقت","الاسم","الرابط","الرابط النهائي","النتيجة","الكود","التحويلات","ms"],...filtered().map(r=>[new Date(r.t).toISOString(),r.n,r.u,r.f,(LABELS[r.s]||LABELS.other)[1],r.c,r.h,r.ms])],"link-log.csv");
if(akey) load(false);
</script>
</body>
</html>`;
