// HeaderSleuth - God Mode (client-only)
// Features: advanced analysis, CSP parse, cookie checks, CORS fuzz generator, HTTP/HTTPS diff, PoC templates, snapshots.

// ---------- Utilities ----------
function normalizeTarget(raw) {
  if (!raw) return '';
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  return raw.replace(/\/+$/,'');
}
function escapeHtml(s) { return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
function severityLabel(score) {
  if (score >= 8) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}
function nowStamp(){ return new Date().toISOString(); }

// ---------- Curl & CORS Generator ----------
function generateCurlTests(target, origins=[], includeCredentials=false, includePreflight=false) {
  const out = [];
  out.push(`# Basic HEAD`);
  out.push(`curl -I -s -D - "${target}" -o /dev/null`);
  out.push(`# Full GET`);
  out.push(`curl -L -s -D - "${target}" -o /dev/null`);
  out.push('');
  // origins tests
  if (origins.length) {
    out.push(`# CORS origin fuzzing`);
    origins.forEach(org => {
      const credFlag = includeCredentials ? ' -H "Cookie: session=BAD" -H "Origin: ' + org + '" ' : ' -H "Origin: ' + org + '" ';
      out.push(`curl -I -s -D - -H "Origin: ${org}" "${target}" -o /dev/null`);
      if (includePreflight) {
        out.push(`# Preflight OPTIONS for ${org}`);
        out.push(`curl -X OPTIONS -i -s -D - -H "Origin: ${org}" -H "Access-Control-Request-Method: POST" "${target}" -o /dev/null`);
      }
    });
    out.push('');
    if (includeCredentials) {
      out.push(`# Credential test (check Access-Control-Allow-Credentials)`);
      out.push(`curl -I -s -D - -H "Origin: https://evil.example.com" -H "Cookie: session=bad" "${target}" -o /dev/null`);
    }
  }
  return out.join('\n');
}

// ---------- Header parsing ----------
function parseRawHeaders(raw) {
  const lines = raw.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  const res = { statusLine:'', headers:{} };
  lines.forEach(line => {
    if (!line.includes(':')) {
      if (/^HTTP\/\d/i.test(line)) res.statusLine = line;
      return;
    }
    const i = line.indexOf(':');
    const name = line.slice(0,i).trim();
    const val = line.slice(i+1).trim();
    const key = name.toLowerCase();
    if (!res.headers[key]) res.headers[key] = [];
    res.headers[key].push(val);
  });
  return res;
}

// ---------- CSP parser ----------
function parseCSP(cspString) {
  // returns map directive -> [values]
  const directives = {};
  const parts = cspString.split(';').map(p => p.trim()).filter(Boolean);
  parts.forEach(p => {
    const idx = p.indexOf(' ');
    if (idx === -1) { directives[p] = []; return; }
    const name = p.slice(0, idx).trim();
    const vals = p.slice(idx+1).trim().split(/\s+/);
    directives[name] = vals;
  });
  return directives;
}

// ---------- Analysis rules ----------
function analyzeHeaders(parsed) {
  const h = parsed.headers;
  const findings = [];
  // HSTS
  if (!h['strict-transport-security']) {
    findings.push({id:'hsts-missing', title:'HSTS missing', severity:9, desc:'Strict-Transport-Security header not present. Recommend HSTS to prevent downgrade attacks.'});
  } else {
    const val = h['strict-transport-security'][0];
    // check max-age threshold
    const m = val.match(/max-age=(\d+)/);
    const maxage = m ? parseInt(m[1],10) : 0;
    if (maxage < 15768000) { // < 6 months
      findings.push({id:'hsts-short', title:'HSTS max-age short', severity:5, desc:`HSTS max-age is ${maxage}. Recommend >= 15768000 (6 months) and includeSubDomains/preload if appropriate.`});
    } else {
      findings.push({id:'hsts-ok', title:'HSTS present', severity:0, desc:'HSTS present with reasonable max-age.'});
    }
  }

  // CSP
  if (!h['content-security-policy']) {
    findings.push({id:'csp-missing', title:'CSP missing', severity:8, desc:'Content-Security-Policy header is missing. CSP reduces XSS risk.'});
  } else {
    const cspRaw = h['content-security-policy'][0];
    const csp = parseCSP(cspRaw);
    const risky = /unsafe-inline|unsafe-eval|data:|blob:/i.test(cspRaw);
    if (risky) findings.push({id:'csp-risky', title:'CSP contains risky directive', severity:8, desc:'CSP contains unsafe-inline/unsafe-eval/data: or blob:, which weakens protections.'});
    else findings.push({id:'csp-ok', title:'CSP present', severity:0, desc:'CSP present; no obvious risky keywords.'});
  }

  // X-Frame-Options or frame-ancestors
  if (!h['x-frame-options'] && !(h['content-security-policy'] && /frame-ancestors/i.test(h['content-security-policy'][0]))) {
    findings.push({id:'clickjacking', title:'Clickjacking defenses missing', severity:7, desc:'No X-Frame-Options or CSP frame-ancestors directive found.'});
  } else {
    findings.push({id:'frame-ok', title:'Clickjacking headers present', severity:0, desc:'X-Frame-Options or frame-ancestors present.'});
  }

  // X-Content-Type-Options
  if (!h['x-content-type-options']) findings.push({id:'xcto-missing', title:'X-Content-Type-Options missing', severity:5, desc:'Missing header; set X-Content-Type-Options: nosniff to reduce MIME sniffing issues.'});

  // Referrer-Policy
  if (!h['referrer-policy']) findings.push({id:'referrer-missing', title:'Referrer-Policy missing', severity:3, desc:'Missing header — consider setting Referrer-Policy to strict-origin-when-cross-origin or no-referrer.'});

  // Permissions-Policy / Feature-Policy
  if (!h['permissions-policy'] && !h['feature-policy']) findings.push({id:'perm-missing', title:'Permissions-Policy missing', severity:3, desc:'Consider restricting powerful features (geolocation, camera, microphone) via Permissions-Policy.'});

  // CORS analysis
  if (h['access-control-allow-origin']) {
    const allow = h['access-control-allow-origin'][0];
    if (allow.trim() === '*') {
      if (h['access-control-allow-credentials']) {
        findings.push({id:'cors-cred-wild', title:'CORS wildcard with credentials', severity:9, desc:'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials is insecure.'});
      } else {
        findings.push({id:'cors-wild', title:'CORS wildcard', severity:5, desc:'Access-Control-Allow-Origin: * — wide exposure for cross-origin reads.'});
      }
    } else {
      findings.push({id:'cors-specific', title:'CORS specific origin or echo', severity:1, desc:`Access-Control-Allow-Origin: ${allow}`});
    }
  } else {
    findings.push({id:'cors-missing', title:'CORS header missing', severity:1, desc:'No Access-Control-Allow-Origin header detected.'});
  }

  // Cookies
  if (h['set-cookie']) {
    h['set-cookie'].forEach(sc => {
      const issues = [];
      if (!/;.*HttpOnly/i.test(sc)) issues.push('missing HttpOnly');
      if (!/;.*Secure/i.test(sc)) issues.push('missing Secure');
      if (!/;.*SameSite=/i.test(sc)) issues.push('missing SameSite');
      if (issues.length) {
        findings.push({id:'cookie-'+btoa(sc).slice(0,6), title:'Cookie weaknesses', severity:7, desc:`Cookie flags: ${issues.join(', ')} — ${sc}`});
      } else {
        findings.push({id:'cookie-ok', title:'Cookie flags present', severity:0, desc:'Cookie has HttpOnly, Secure and SameSite.'});
      }
    });
  } else {
    findings.push({id:'cookie-none', title:'No cookies set', severity:0, desc:'No Set-Cookie headers present.'});
  }

  // SRI check hint (if script tags provided to paste elsewhere)
  // Additional heuristics can be added here (CSP host wildcards, overly permissive origins, etc.)

  // assign severity label & return
  return findings.map(f => ({...f, severityLabel: severityLabel(f.severity)}));
}

// ---------- Render helpers ----------
function renderFindings(list) {
  if (!list || !list.length) return '<p>No findings.</p>';
  const grouped = list.filter(f => f.severity > 0).sort((a,b)=>b.severity-a.severity);
  const ok = list.filter(f => f.severity === 0);
  let html = '';
  html += `<div class="summary"><strong>${grouped.length}</strong> issues flagged. <em>${ok.length}</em> informational items.</div>`;
  grouped.forEach(f => {
    html += `<div class="finding ${f.severityLabel}"><h4>${escapeHtml(f.title)} <span class="sev">${f.severityLabel.toUpperCase()}</span></h4><p>${escapeHtml(f.desc)}</p><button data-id="${escapeHtml(f.id)}" class="make-poc">Generate PoC</button></div>`;
  });
  ok.forEach(f => {
    html += `<div class="finding ok"><h4>${escapeHtml(f.title)}</h4><p>${escapeHtml(f.desc)}</p></div>`;
  });
  return html;
}

// ---------- PoC generator ----------
function generatePoC(target, finding) {
  const t = target;
  let md = `### Finding: ${finding.title}\n\n**Severity:** ${finding.severityLabel}\n\n**Description:** ${finding.desc}\n\n**Repro (run locally):**\n\`\`\`bash\n# Basic headers\ncurl -I -s -D - "${t}" -o /dev/null\n\`\`\`\n`;
  if (finding.id.startsWith('cors')) {
    md += `\n**CORS PoC:**\n\`\`\`bash\ncurl -I -s -D - -H "Origin: https://evil.example.com" "${t}" -o /dev/null\n\`\`\`\n`;
  }
  if (finding.title.toLowerCase().includes('cookie')) {
    md += `\n**Cookie check:** run a full GET and review Set-Cookie:\n\`\`\`bash\ncurl -L -s -D - "${t}" -o /dev/null\n\`\`\`\n`;
  }
  md += `\n**Suggested remediation:** (brief) — ${suggestedRemediation(finding.id)}\n`;
  return md;
}
function suggestedRemediation(id){
  if (id.startsWith('hsts')) return 'Enable HSTS with a long max-age and includeSubDomains; consider preload after review.';
  if (id.startsWith('csp')) return 'Tighten CSP: remove unsafe-inline/eval and avoid wide source lists.';
  if (id.startsWith('clickjacking')) return 'Add X-Frame-Options or CSP frame-ancestors to prevent framing.';
  if (id.startsWith('cors')) return 'Avoid echoing arbitrary origins and do not combine wildcard origin with credentials.';
  if (id.startsWith('cookie')) return 'Set Secure, HttpOnly, and SameSite attributes appropriately.';
  return 'Review and apply standard security header best practices.';
}

// ---------- Snapshot management ----------
function saveSnapshot(name, parsed) {
  const key = 'hs_snap_' + (name || nowStamp());
  const payload = {name, parsed, ts: nowStamp()};
  localStorage.setItem(key, JSON.stringify(payload));
  return key;
}
function listSnapshots() {
  const out = [];
  for (let i=0;i<localStorage.length;i++){
    const k = localStorage.key(i);
    if (k && k.startsWith('hs_snap_')) out.push({key:k, val:JSON.parse(localStorage.getItem(k))});
  }
  return out.sort((a,b)=> b.val.ts.localeCompare(a.val.ts));
}

// ---------- Wiring UI ----------
document.getElementById('genAll').addEventListener('click', ()=>{
  const t = normalizeTarget(document.getElementById('target').value);
  const origins = document.getElementById('origins').value.split(',').map(s=>s.trim()).filter(Boolean);
  const cred = document.getElementById('cred').checked;
  const pre = document.getElementById('preflight').checked;
  document.getElementById('curlOutput').textContent = t ? generateCurlTests(t, origins, cred, pre) : '# Enter target first';
});
document.getElementById('copyCurl').addEventListener('click', ()=>{
  navigator.clipboard.writeText(document.getElementById('curlOutput').textContent);
});

// Analyze A
document.getElementById('analyzeA').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteA').value;
  const parsed = parseRawHeaders(raw);
  const findings = analyzeHeaders(parsed);
  document.getElementById('findings').innerHTML = renderFindings(findings);
  // hook PoC buttons
  document.querySelectorAll('.make-poc').forEach(btn => {
    btn.onclick = () => {
      const id = btn.getAttribute('data-id');
      const f = findings.find(x=>x.id===id);
      const target = normalizeTarget(document.getElementById('target').value) || '[TARGET]';
      const md = generatePoC(target, f);
      document.getElementById('poc').textContent = md;
    };
  });
});

// Analyze B
document.getElementById('analyzeB').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteB').value;
  const parsed = parseRawHeaders(raw);
  const findings = analyzeHeaders(parsed);
  // append results to findings area prefixed
  const existing = document.getElementById('findings').innerHTML;
  document.getElementById('findings').innerHTML = existing + '<hr/>' + renderFindings(findings);
  document.querySelectorAll('.make-poc').forEach(btn => {
    btn.onclick = () => {
      const id = btn.getAttribute('data-id');
      const f = findings.find(x=>x.id===id);
      const target = normalizeTarget(document.getElementById('target').value) || '[TARGET]';
      const md = generatePoC(target, f);
      document.getElementById('poc').textContent = md;
    };
  });
});

// Diff A ↔ B
document.getElementById('diffAB').addEventListener('click', ()=>{
  const pa = parseRawHeaders(document.getElementById('pasteA').value);
  const pb = parseRawHeaders(document.getElementById('pasteB').value);
  if (!pa.headers || !pb.headers) { document.getElementById('findings').innerHTML = '<p class="warn">Paste both A and B to diff.</p>'; return; }
  // collect keys
  const keys = Array.from(new Set([...Object.keys(pa.headers), ...Object.keys(pb.headers)])).sort();
  let html = '<h4>Header Differences</h4><table class="diff"><tr><th>Header</th><th>A</th><th>B</th></tr>';
  keys.forEach(k => {
    const a = pa.headers[k] ? pa.headers[k].join(' | ') : '';
    const b = pb.headers[k] ? pb.headers[k].join(' | ') : '';
    const cls = (a===b) ? 'same' : 'diff';
    html += `<tr class="${cls}"><td>${escapeHtml(k)}</td><td>${escapeHtml(a)}</td><td>${escapeHtml(b)}</td></tr>`;
  });
  html += '</table>';
  document.getElementById('findings').innerHTML = html;
});

// Snapshots
document.getElementById('saveA').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteA').value;
  const parsed = parseRawHeaders(raw);
  const key = saveSnapshot('A-'+nowStamp(), parsed);
  alert('Saved snapshot: ' + key);
});
document.getElementById('saveB').addEventListener('click', ()=>{
  const raw = document.getElementById('pasteB').value;
  const parsed = parseRawHeaders(raw);
  const key = saveSnapshot('B-'+nowStamp(), parsed);
  alert('Saved snapshot: ' + key);
});
document.getElementById('listSnapshots').addEventListener('click', ()=>{
  const list = listSnapshots();
  const el = document.getElementById('snapshotList');
  if (!list.length) { el.innerHTML = '<p>No snapshots</p>'; return; }
  el.innerHTML = list.map(s => `<div class="snapitem"><code>${s.key}</code> <button data-k="${s.key}" class="loadsnap">Load</button> <button data-k="${s.key}" class="delsnap">Delete</button></div>`).join('');
  document.querySelectorAll('.loadsnap').forEach(b => b.onclick = (e)=> {
    const k = e.target.getAttribute('data-k');
    const obj = JSON.parse(localStorage.getItem(k));
    document.getElementById('pasteA').value = (obj.parsed.statusLine ? obj.parsed.statusLine + '\n' : '') + Object.entries(obj.parsed.headers).map(([kk,vs])=> vs.map(v=> `${kk}: ${v}`).join('\n')).join('\n');
    alert('Loaded into A: ' + k);
  });
  document.querySelectorAll('.delsnap').forEach(b => b.onclick = (e)=> {
    const k = e.target.getAttribute('data-k');
    localStorage.removeItem(k);
    alert('Deleted ' + k);
  });
});

// Export report (MD) - basic: combine findings and PoC
document.getElementById('exportReport').addEventListener('click', ()=>{
  const md = '# HeaderSleuth Report\n\n' + document.getElementById('poc').textContent + '\n\nGenerated: ' + nowStamp();
  const blob = new Blob([md], {type:'text/markdown'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'headersleuth-report.md'; a.click(); URL.revokeObjectURL(url);
});

// Export CSV placeholder (would collect findings)
document.getElementById('exportCSV').addEventListener('click', ()=>{
  // simple CSV demo: capture findings title,severity,desc from currently rendered findings (not structured)
  const csv = 'title,severity,desc\n' + '"Sample","low","demo"\n';
  const blob = new Blob([csv], {type:'text/csv'}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'findings.csv'; a.click(); URL.revokeObjectURL(url);
});

// PoC buttons in rendered findings are wired during render after analyze (see analyzeA/analyzeB)
