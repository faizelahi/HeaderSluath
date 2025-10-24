// HeaderSleuth++ Phase1 - client only
// Utility helpers
function normalizeTarget(raw){
  if (!raw) return '';
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  return raw.replace(/\/+$/,'');
}
function escapeHtml(s){ return s ? s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;') : ''; }
function nowISO(){ return new Date().toISOString(); }
function downloadFile(filename, content){
  const blob = new Blob([content], {type:'text/plain'}); const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}

// ---------- Curl & CORS generator ----------
function genCurl(target, origins, includeCreds, includePreflight){
  const out = [];
  out.push('# Basic HEAD');
  out.push(`curl -I -s -D - "${target}" -o /dev/null`);
  out.push('');
  out.push('# Full GET (follow redirects)');
  out.push(`curl -L -s -D - "${target}" -o /dev/null`);
  out.push('');
  if (origins.length){
    out.push('# CORS origin tests');
    origins.forEach(org=>{
      out.push(`curl -I -s -D - -H "Origin: ${org}" "${target}" -o /dev/null`);
      if (includePreflight){
        out.push(`# Preflight for ${org}`);
        out.push(`curl -X OPTIONS -i -s -D - -H "Origin: ${org}" -H "Access-Control-Request-Method: POST" "${target}" -o /dev/null`);
      }
    });
    if (includeCreds){
      out.push('# Credentials test (check Access-Control-Allow-Credentials)');
      out.push(`curl -I -s -D - -H "Origin: ${origins[0]}" -H "Cookie: session=bad" "${target}" -o /dev/null`);
    }
  }
  return out.join('\n');
}
document.getElementById('genCurl').addEventListener('click', ()=>{
  const t = normalizeTarget(document.getElementById('target').value);
  const origins = document.getElementById('origins').value.split(',').map(s=>s.trim()).filter(Boolean);
  const cred = document.getElementById('cred').checked;
  const pre = document.getElementById('preflight').checked;
  document.getElementById('curlOutput').textContent = t ? genCurl(t, origins, cred, pre) : '# Enter a valid target first';
});
document.getElementById('copyCurl').addEventListener('click', ()=> navigator.clipboard.writeText(document.getElementById('curlOutput').textContent));
document.getElementById('downloadCurl').addEventListener('click', ()=> downloadFile('cors_tests.sh', document.getElementById('curlOutput').textContent));

// ---------- Header parsing & analysis ----------
function parseHeaders(raw){
  const lines = raw.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  const res = {status:'', headers:{}};
  lines.forEach(line=>{
    if (!line.includes(':')){
      if (/^HTTP\/\d/i.test(line)) res.status = line;
      return;
    }
    const i = line.indexOf(':'); const name = line.slice(0,i).trim(); const val = line.slice(i+1).trim();
    const k = name.toLowerCase();
    if (!res.headers[k]) res.headers[k]=[];
    res.headers[k].push(val);
  });
  return res;
}

function analyze(parsed){
  const h = parsed.headers;
  const results = [];
  // HSTS
  if (!h['strict-transport-security']) results.push({id:'hsts-miss', title:'HSTS missing', sev:9, desc:'Strict-Transport-Security not set.'});
  else {
    const v = h['strict-transport-security'][0];
    const m = v.match(/max-age=(\d+)/); const age = m?parseInt(m[1],10):0;
    if (age < 15768000) results.push({id:'hsts-short', title:'HSTS max-age short', sev:5, desc:`HSTS max-age ${age}`});
    else results.push({id:'hsts-ok', title:'HSTS present', sev:0, desc:`HSTS: ${v}`});
  }
  // CSP
  if (!h['content-security-policy']) results.push({id:'csp-miss', title:'CSP missing', sev:8, desc:'Content-Security-Policy not present.'});
  else {
    const raw = h['content-security-policy'][0];
    if (/unsafe-inline|unsafe-eval|data:|blob:/i.test(raw)) results.push({id:'csp-risk', title:'CSP risky directives', sev:8, desc:`CSP contains unsafe keywords: ${raw}`});
    else results.push({id:'csp-ok', title:'CSP present', sev:0, desc:`CSP: ${raw}`});
  }
  // Clickjacking
  if (!h['x-frame-options'] && !(h['content-security-policy'] && /frame-ancestors/i.test(h['content-security-policy'][0]))) results.push({id:'frame-miss', title:'Frame protection missing', sev:7, desc:'No X-Frame-Options or frame-ancestors.'});
  else results.push({id:'frame-ok', title:'Frame protection', sev:0, desc:'Frame protection present.'});
  // X-Content-Type-Options
  if (!h['x-content-type-options']) results.push({id:'xcto', title:'X-Content-Type-Options missing', sev:5, desc:'Add X-Content-Type-Options: nosniff.'});
  // Referrer
  if (!h['referrer-policy']) results.push({id:'ref-miss', title:'Referrer-Policy missing', sev:3, desc:'Consider setting Referrer-Policy.'});
  // Permissions-Policy
  if (!h['permissions-policy'] && !h['feature-policy']) results.push({id:'perm-miss', title:'Permissions-Policy missing', sev:3, desc:'Consider restricting features via Permissions-Policy.'});
  // CORS
  if (h['access-control-allow-origin']){
    const val = h['access-control-allow-origin'][0];
    if (val.trim()==='*'){
      if (h['access-control-allow-credentials']) results.push({id:'cors-wild-cred', title:'CORS * + credentials', sev:9, desc:'Wildcard origin with credentials header present.'});
      else results.push({id:'cors-wild', title:'CORS wildcard', sev:5, desc:'Access-Control-Allow-Origin: *'});
    } else results.push({id:'cors-ok', title:'CORS: specific origin', sev:1, desc:`Access-Control-Allow-Origin: ${val}`});
  } else results.push({id:'cors-none', title:'CORS header missing', sev:1, desc:'No Access-Control-Allow-Origin detected.'});
  // Cookies
  if (h['set-cookie']){
    h['set-cookie'].forEach(sc=>{
      const missing = [];
      if (!/;.*HttpOnly/i.test(sc)) missing.push('HttpOnly');
      if (!/;.*Secure/i.test(sc)) missing.push('Secure');
      if (!/;.*SameSite=/i.test(sc)) missing.push('SameSite');
      if (missing.length) results.push({id:'cookie-weak', title:'Cookie flags missing', sev:7, desc:`Cookie: ${sc} — missing: ${missing.join(', ')}`});
      else results.push({id:'cookie-ok', title:'Cookie flags present', sev:0, desc:'Cookie has HttpOnly, Secure, SameSite'});
    });
  } else results.push({id:'cookie-none', title:'No cookies set', sev:0, desc:'No Set-Cookie headers.'});
  return results;
}

function renderFindings(list){
  if (!list.length) return '<p>No findings.</p>';
  const high = list.filter(l=>l.sev>=7), med = list.filter(l=>l.sev>=4 && l.sev<7), low = list.filter(l=>l.sev<4 && l.sev>0), ok = list.filter(l=>l.sev===0);
  let html = '';
  [high, med, low, ok].forEach(group=>{
    group.forEach(f=>{
      const cls = f.sev>=7?'high':(f.sev>=4?'medium':'low');
      html += `<div class="finding ${cls}"><h4>${escapeHtml(f.title)} <small>(${f.sev})</small></h4><p>${escapeHtml(f.desc)}</p><button class="pocbtn" data-id="${escapeHtml(f.id)}">Generate PoC</button></div>`;
    });
  });
  return html;
}

// ---------- UI wiring ----------
const analysisEl = document.getElementById('analysis'), findingsEl = document.getElementById('findings'), pocEl = document.getElementById('poc');
let lastFindingsA = [], lastFindingsB = [];

document.getElementById('analyzeA').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteA').value;
  if (!raw.trim()){ analysisEl.innerHTML = '<p class="note">Paste headers for A first.</p>'; return; }
  const parsed = parseHeaders(raw);
  const res = analyze(parsed);
  lastFindingsA = res;
  analysisEl.innerHTML = `<strong>A parsed:</strong><br/><pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>`;
  findingsEl.innerHTML = renderFindings(res);
  wirePoCButtons(res);
});

document.getElementById('analyzeB').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteB').value;
  if (!raw.trim()){ analysisEl.innerHTML = '<p class="note">Paste headers for B first.</p>'; return; }
  const parsed = parseHeaders(raw);
  const res = analyze(parsed);
  lastFindingsB = res;
  analysisEl.innerHTML = `<strong>B parsed:</strong><br/><pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>`;
  findingsEl.innerHTML = renderFindings(res);
  wirePoCButtons(res);
});

function wirePoCButtons(list){
  document.querySelectorAll('.pocbtn').forEach(b=>{
    b.onclick = ()=> {
      const id = b.getAttribute('data-id');
      const f = list.find(x=>x.id===id);
      const target = normalizeTarget(document.getElementById('target').value) || '[TARGET]';
      if (!f) return;
      const md = generatePoC(target, f);
      pocEl.textContent = md;
    };
  });
}

// Diff A vs B
document.getElementById('diffAB').addEventListener('click', ()=>{
  const pa = parseHeaders(document.getElementById('pasteA').value);
  const pb = parseHeaders(document.getElementById('pasteB').value);
  if (!Object.keys(pa.headers).length || !Object.keys(pb.headers).length){ findingsEl.innerHTML = '<p class="note">Paste both A and B to diff.</p>'; return; }
  const keys = Array.from(new Set([...Object.keys(pa.headers), ...Object.keys(pb.headers)])).sort();
  let html = '<h4>Header differences (A vs B)</h4><table><tr><th>Header</th><th>A</th><th>B</th></tr>';
  keys.forEach(k=>{
    const a = pa.headers[k]?pa.headers[k].join(' | '):'';
    const b = pb.headers[k]?pb.headers[k].join(' | '):'';
    const cls = a===b?'same':'diff';
    html += `<tr class="${cls}"><td>${escapeHtml(k)}</td><td>${escapeHtml(a)}</td><td>${escapeHtml(b)}</td></tr>`;
  });
  html += '</table>';
  findingsEl.innerHTML = html;
});

// PoC generator
function generatePoC(target, finding){
  let md = `# Finding: ${finding.title}\n\n**Severity:** ${finding.sev}\n\n**Details:** ${finding.desc}\n\n**Repro (local):**\n\`\`\`bash\ncurl -I -s -D - "${target}" -o /dev/null\n\`\`\`\n`;
  if (finding.id.includes('cors')) md += `\nCORS PoC (run locally):\n\`\`\`bash\ncurl -I -s -D - -H "Origin: https://evil.example.com" "${target}" -o /dev/null\n\`\`\`\n`;
  if (finding.id.startsWith('cookie')) md += `\nCookie check:\n\`\`\`bash\ncurl -L -s -D - "${target}" -o /dev/null\n\`\`\`\n`;
  md += `\n**Suggested remediation:** ${suggestedFix(finding.id)}\n`;
  return md;
}
function suggestedFix(id){
  if (id.startsWith('hsts')) return 'Enable Strict-Transport-Security with a long max-age and includeSubDomains.';
  if (id.startsWith('csp')) return 'Add or tighten Content-Security-Policy; avoid unsafe-inline/eval.';
  if (id.includes('cookie')) return 'Set Secure, HttpOnly and SameSite attributes for cookies.';
  if (id.includes('cors')) return 'Avoid wildcard origins and do not combine wildcard with credentials.';
  return 'Review header and apply best-practice security headers.';
}
document.getElementById('exportMD').addEventListener('click', ()=>{
  const md = pocEl.textContent || '# No PoC generated';
  downloadFile('headersleuth-poc.md', md);
});

// Snapshots (localStorage)
function saveSnapshot(name, raw){
  const key = 'hs_snap_' + (name || nowISO());
  const obj = {name, ts: nowISO(), raw};
  localStorage.setItem(key, JSON.stringify(obj));
  alert('Saved snapshot: ' + key);
}
document.getElementById('saveA').addEventListener('click', ()=> saveSnapshot('A-'+nowISO(), document.getElementById('pasteA').value));
document.getElementById('saveB').addEventListener('click', ()=> saveSnapshot('B-'+nowISO(), document.getElementById('pasteB').value));
document.getElementById('listSnaps').addEventListener('click', ()=>{
  const out = [];
  for (let i=0;i<localStorage.length;i++){
    const k = localStorage.key(i);
    if (k && k.startsWith('hs_snap_')) out.push({k, v: JSON.parse(localStorage.getItem(k))});
  }
  const el = document.getElementById('snapList');
  if (!out.length) { el.innerHTML = '<p>No snapshots</p>'; return; }
  el.innerHTML = out.map(o=>`<div class="snapitem"><code>${o.k}</code><div><button data-k="${o.k}" class="load">Load</button> <button data-k="${o.k}" class="del">Delete</button></div></div>`).join('');
  document.querySelectorAll('.load').forEach(b=> b.onclick = e=>{
    const k = e.target.getAttribute('data-k');
    const obj = JSON.parse(localStorage.getItem(k));
    document.getElementById('pasteA').value = obj.raw || '';
    alert('Loaded into A from ' + k);
  });
  document.querySelectorAll('.del').forEach(b=> b.onclick = e=>{
    const k = e.target.getAttribute('data-k'); localStorage.removeItem(k); alert('Deleted ' + k); document.getElementById('listSnaps').click();
  });
});