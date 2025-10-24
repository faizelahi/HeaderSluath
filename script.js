/******************************************************************************
 * HeaderSleuth++ - MONSTER script.js
 * Purpose: God-mode client-side header analysis, CORS fuzz, cookie audit,
 *          CSP analysis, fingerprinting, PoC generation, snapshot diffing, etc.
 * Author: generated (FaizGPT-assist)
 * Notes: Pure client-side. DOES NOT fetch remote hosts. Generates scripts only.
 ******************************************************************************/

/* eslint-disable no-unused-vars */
/* Large, modular, closure-based implementation to be pasted as script.js */

(() => {
  'use strict';

  /**************************************************************************
   * Top-level runtime guard & environment setup
   **************************************************************************/
  const HS = {}; // namespace
  HS.VERSION = '2.0.0-god';
  HS.DEBUG = true;

  function log(...args) {
    if (HS.DEBUG) console.log('[HS]', ...args);
  }
  function warn(...args) { console.warn('[HS]', ...args); }
  function err(...args) { console.error('[HS]', ...args); }

  // small polyfills if needed
  if (!String.prototype.replaceAll) {
    // naive polyfill
    // eslint-disable-next-line no-extend-native
    String.prototype.replaceAll = function (s, r) { return this.split(s).join(r); };
  }

  /**************************************************************************
   * Utilities module (many helpers)
   **************************************************************************/
  HS.utils = (() => {
    const u = {};

    u.$ = (id) => document.getElementById(id);
    u.exists = (id) => !!u.$(id);
    u.trim = (s) => (s == null ? '' : String(s).trim());
    u.now = () => new Date().toISOString();
    u.safeText = (s) => String(s || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    u.clone = (o) => JSON.parse(JSON.stringify(o));
    u.isEmpty = (o) => (o === null || o === undefined || (typeof o === 'object' && Object.keys(o).length === 0) || (typeof o === 'string' && o.trim() === ''));

    u.download = (filename, content, mime = 'text/plain') => {
      const blob = new Blob([content], { type: mime + ';charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };

    u.copyToClipboard = async (text) => {
      if (!navigator.clipboard) {
        // fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); document.body.removeChild(ta); return true; } catch (e) { document.body.removeChild(ta); return false; }
      }
      try { await navigator.clipboard.writeText(text); return true; } catch (e) { return false; }
    };

    u.slug = (s) => (String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''));

    u.safeJSONparse = (txt) => { try { return JSON.parse(txt); } catch (e) { return null; } };

    u.mergeUnique = (a, b, key) => {
      const map = new Map();
      a.concat(b || []).forEach(it => map.set(it[key] || JSON.stringify(it), it));
      return Array.from(map.values());
    };

    u.tuplesToObj = (arr) => {
      const obj = {};
      (arr || []).forEach(([k, v]) => { obj[k] = v; });
      return obj;
    };

    u.sleep = (ms) => new Promise(r => setTimeout(r, ms));

    return u;
  })();

  /**************************************************************************
   * DOM readiness / safer binding
   **************************************************************************/
  HS.domReady = (fn) => {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  };

  /**************************************************************************
   * Core: header parsing & normalization engines
   **************************************************************************/
  HS.parser = (() => {
    const p = {};

    p.normalizeTarget = (raw) => {
      let r = HS.utils.trim(raw);
      if (!r) return '';
      // preserve scheme if present; default to https
      if (!/^https?:\/\//i.test(r)) r = 'https://' + r;
      // strip trailing fragment + query for canonical host analysis (but keep for curl generation)
      // return both raw and canonical
      const canonical = r.replace(/\/+$/, '').replace(/\?.*$/, '').replace(/#.*$/, '');
      return { raw: r, canonical };
    };

    p.splitLines = (txt) => {
      if (!txt) return [];
      // unify CRLF and CR
      return String(txt).split(/\r\n|\r|\n/).map(l => l.replace(/\u00A0/g, ' ').trim()).filter(Boolean);
    };

    p.parseRawHeaders = (raw) => {
      // raw: string containing headers (curl -I or devtools)
      const lines = p.splitLines(raw);
      const res = { statusLine: '', headers: {} };
      lines.forEach(line => {
        // status line or header
        if (!line.includes(':')) {
          if (/^HTTP\/\d/i.test(line)) res.statusLine = line;
          return;
        }
        const idx = line.indexOf(':');
        const name = line.slice(0, idx).trim();
        const val = line.slice(idx + 1).trim();
        const key = name.toLowerCase();
        if (!res.headers[key]) res.headers[key] = [];
        res.headers[key].push(val);
      });
      return res;
    };

    p.normalizeHeaderKey = (k) => String(k || '').toLowerCase().trim();

    p.headersToString = (parsed) => {
      if (!parsed || !parsed.headers) return '';
      const parts = [];
      if (parsed.statusLine) parts.push(parsed.statusLine);
      Object.keys(parsed.headers).forEach(k => {
        (parsed.headers[k] || []).forEach(v => parts.push(`${k}: ${v}`));
      });
      return parts.join('\n');
    };

    // produce canonical header map (single string values joined by ' | ')
    p.canonicalHeaderMap = (parsed) => {
      const out = {};
      (parsed && parsed.headers) && Object.keys(parsed.headers).forEach(k => { out[k] = parsed.headers[k].join(' | '); });
      if (parsed.statusLine) out['_status'] = parsed.statusLine;
      return out;
    };

    return p;
  })();

  /**************************************************************************
   * Heuristics & detectors (CSP, CORS, Cookies, Fingerprinting, SRI)
   **************************************************************************/
  HS.detectors = (() => {
    const d = {};

    /******************************
     * CSP analysis
     ******************************/
    d.parseCSP = (cspString) => {
      // returns a normalized object: directive -> [values]
      const obj = {};
      if (!cspString) return obj;
      // split on semicolon but respect quoted tokens (simple)
      const parts = cspString.split(';').map(p => p.trim()).filter(Boolean);
      parts.forEach(p => {
        const sp = p.split(/\s+/);
        const dir = sp[0];
        const vals = sp.slice(1).map(s => s.trim()).filter(Boolean);
        obj[dir] = vals;
      });
      return obj;
    };

    d.cspRiskScore = (cspString) => {
      // heuristics: unsafe-inline, unsafe-eval, data:, blob:, wildcard *
      let score = 100;
      if (!cspString) return { score: 0, notes: ['CSP missing'] };
      if (/unsafe-inline/i.test(cspString)) { score -= 40; }
      if (/unsafe-eval/i.test(cspString)) { score -= 25; }
      if (/data:/i.test(cspString)) { score -= 20; }
      if (/blob:/i.test(cspString)) { score -= 15; }
      if (/\*\s*/.test(cspString)) { score -= 30; }
      return { score: Math.max(0, score), notes: [] };
    };

    d.cspBypassHints = (cspObj) => {
      // give human-friendly hints for likely bypass paths
      const hints = [];
      if (!cspObj || Object.keys(cspObj).length === 0) { hints.push('No CSP found — high XSS risk.'); return hints; }
      if (cspObj['script-src']) {
        const s = cspObj['script-src'].join(' ');
        if (/\bunsafe-inline\b/i.test(s)) hints.push('script-src allows unsafe-inline — inline XSS may be possible.');
        if (/\bunsafe-eval\b/i.test(s)) hints.push('script-src allows unsafe-eval — eval-based constructs may work.');
        if (/\*/.test(s)) hints.push('script-src contains wildcard — remote scripts may be allowed from any origin.');
        if (/data:/i.test(s)) hints.push('script-src allows data: — data URI injections may be possible.');
      }
      if (cspObj['default-src']) {
        const s = cspObj['default-src'].join(' ');
        if (/\*/.test(s)) hints.push('default-src wildcard present — broad allowances may weaken CSP.');
      }
      return hints;
    };

    /******************************
     * CORS analysis
     ******************************/
    d.analyzeCORS = (headers) => {
      // headers: canonical header map
      const out = [];
      const aco = headers['access-control-allow-origin'] ? headers['access-control-allow-origin'] : null;
      const acc = headers['access-control-allow-credentials'] ? headers['access-control-allow-credentials'] : null;
      const acam = headers['access-control-allow-methods'] ? headers['access-control-allow-methods'] : null;
      const acah = headers['access-control-allow-headers'] ? headers['access-control-allow-headers'] : null;

      if (!aco) { out.push({ id: 'cors-missing', title: 'CORS header missing', sev: 2, desc: 'Access-Control-Allow-Origin not present' }); return out; }
      const val = aco.trim();
      if (val === '*') {
        if (acc && /true/i.test(acc)) {
          out.push({ id: 'cors-wild-cred', title: 'CORS wildcard with credentials', sev: 10, desc: 'Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true — insecure.' });
        } else {
          out.push({ id: 'cors-wild', title: 'CORS wildcard', sev: 5, desc: 'Access-Control-Allow-Origin: * — broad access for cross-origin reads.' });
        }
      } else {
        // heuristics for echoing origin or reflecting
        if (/^https?:\/\//i.test(val) && val.indexOf('{') !== -1) {
          out.push({ id: 'cors-echo-dynamic', title: 'CORS origin echo or templated', sev: 7, desc: `Access-Control-Allow-Origin may reflect incoming Origin (${val}) — potential misconfiguration.` });
        } else {
          out.push({ id: 'cors-ok', title: 'Specific CORS origin', sev: 0, desc: `Access-Control-Allow-Origin: ${val}` });
        }
      }
      if (acam && /PUT|DELETE|PATCH/i.test(acam)) {
        out.push({ id: 'cors-methods', title: 'CORS allows non-safe methods', sev: 4, desc: `Access-Control-Allow-Methods: ${acam}` });
      }
      if (acah && /\*/.test(acah)) {
        out.push({ id: 'cors-headers-wild', title: 'CORS allows any header', sev: 4, desc: `Access-Control-Allow-Headers: ${acah}` });
      }
      return out;
    };

    /******************************
     * Cookie analysis
     ******************************/
    d.analyzeCookies = (headers) => {
      const out = [];
      const cookies = headers['set-cookie'] ? (Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']]) : [];
      if (!cookies.length) { out.push({ id: 'cookie-none', title: 'No cookies set', sev: 0, desc: 'No Set-Cookie headers present.' }); return out; }

      const seenNames = new Map();
      cookies.forEach(scRaw => {
        const sc = scRaw + '';
        // parse name
        const nameMatch = sc.match(/^([^=;]+)=/);
        const name = nameMatch ? nameMatch[1] : '(unknown)';
        // flags check
        const hasHttpOnly = /;\s*httponly/i.test(sc);
        const hasSecure = /;\s*secure/i.test(sc);
        const samesiteMatch = sc.match(/;\s*samesite=([^;]+)/i);
        const samesite = samesiteMatch ? samesiteMatch[1] : null;
        const expMatch = sc.match(/;\s*expires=([^;]+)/i);
        const expiresRaw = expMatch ? expMatch[1] : null;
        let expiresDanger = false;
        if (expiresRaw) {
          const date = new Date(expiresRaw);
          if (!Number.isNaN(date.getTime())) {
            const diff = date.getTime() - Date.now();
            // > 1 year considered long-lived
            if (diff > 365 * 24 * 3600 * 1000) expiresDanger = true;
          }
        }
        // rules
        const problems = [];
        if (!hasHttpOnly) problems.push('missing HttpOnly');
        if (!hasSecure) problems.push('missing Secure');
        if (!samesite) problems.push('missing SameSite');
        if (samesite && /none/i.test(samesite) && !hasSecure) problems.push('SameSite=None without Secure');
        if (expiresDanger) problems.push('Expiration >1 year');

        // duplicate name detection
        if (seenNames.has(name)) {
          problems.push('duplicate cookie name (possible conflicting scopes)');
        } else seenNames.set(name, true);

        const sev = problems.length ? 7 : 0;
        out.push({ id: `cookie-${HS.utils.slug(name)}-${seenNames.size}`, title: `Cookie: ${name}`, sev, desc: `${sc} — ${problems.length ? 'Issues: ' + problems.join(', ') : 'Flags OK'}` });
      });

      return out;
    };

    /******************************
     * Fingerprinting & version hints (no network calls)
     ******************************/
    d.fingerprint = (headers) => {
      const out = [];
      const candidates = [];
      const server = headers['server'] || headers['x-powered-by'] || headers['via'] || null;
      if (server) {
        const s = (Array.isArray(server) ? server.join(' | ') : server) + '';
        candidates.push({ name: 'server', val: s });
        // heuristic patterns (not exhaustive)
        const patterns = [
          { re: /nginx\/([\d\.]+)/i, product: 'nginx', ver: 1 },
          { re: /cloudflare/i, product: 'cloudflare', ver: 0 },
          { re: /Apache\/([\d\.]+)/i, product: 'Apache HTTP Server', ver: 1 },
          { re: /gunicorn/i, product: 'gunicorn', ver: 0 },
          { re: /Express/i, product: 'Express (Node.js)', ver: 0 },
          { re: /GSE/i, product: 'Google Frontend', ver: 0 }
        ];
        patterns.forEach(pat => {
          const m = s.match(pat.re);
          if (m) {
            const ver = m[1] || '';
            out.push({ id: `fp-${pat.product}`, title: `Fingerprint: ${pat.product}`, sev: 1, desc: `${pat.product}${ver ? ' ' + ver : ''} (${s})` });
          }
        });
      } else {
        out.push({ id: 'fp-none', title: 'Fingerprint not found', sev: 0, desc: 'No server or X-Powered-By headers found' });
      }
      return out;
    };

    /******************************
     * SRI (Subresource Integrity) checker helper
     ******************************/
    d.sriCheck = (tagString) => {
      // expects a tag string like: <script src="..." integrity="sha256-...">
      const integrityMatch = String(tagString || '').match(/integrity\s*=\s*"(.*?)"/i);
      if (!integrityMatch) return { ok: false, reason: 'No integrity attribute found' };
      const value = integrityMatch[1];
      // simple format checks
      if (!/^(sha256|sha384|sha512)-[A-Za-z0-9+/=]+$/.test(value)) return { ok: false, reason: 'Integrity format invalid' };
      return { ok: true, algo: value.split('-')[0], hash: value.split('-')[1], value };
    };

    return {
      parseCSP: d.parseCSP,
      cspRiskScore: d.cspRiskScore,
      cspBypassHints: d.cspBypassHints,
      analyzeCORS: d.analyzeCORS,
      analyzeCookies: d.analyzeCookies,
      fingerprint: d.fingerprint,
      sriCheck: d.sriCheck
    };
  })();

  /**************************************************************************
   * Scoring & aggregation engine
   **************************************************************************/
  HS.scorer = (() => {
    const s = {};

    s.computeScore = (findings) => {
      // base 100, subtract weighted penalties
      let score = 100;
      (findings || []).forEach(f => {
        const sev = f.sev || 0;
        // map severity to penalty
        if (sev >= 10) score -= 30;
        else if (sev >= 8) score -= 25;
        else if (sev >= 6) score -= 18;
        else if (sev >= 4) score -= 10;
        else if (sev >= 2) score -= 4;
      });
      score = Math.max(0, Math.min(100, score));
      // normalize: if no findings but headers empty => score 0
      return Math.round(score);
    };

    s.scoreColor = (score) => {
      if (score >= 80) return 'green';
      if (score >= 50) return 'orange';
      return 'red';
    };

    return s;
  })();

  /**************************************************************************
   * PoC & script generator (lots of variants)
   **************************************************************************/
  HS.poc = (() => {
    const p = {};

    p.generateCurlBasic = (target) => {
      return `# Basic header fetch (local)\ncurl -I -s -D - "${target}" -o /dev/null\n# Full GET (follow redirects)\ncurl -L -s -D - "${target}" -o /dev/null\n`;
    };

    p.generateCORSpoC = (target, origin = 'https://evil.example.com', preflight = false, credentials = false) => {
      const lines = [];
      lines.push(`# CORS Origin test for ${origin}`);
      lines.push(`curl -I -s -D - -H "Origin: ${origin}" "${target}" -o /dev/null`);
      if (preflight) lines.push(`# Preflight (OPTIONS)`);
      if (preflight) lines.push(`curl -X OPTIONS -i -s -D - -H "Origin: ${origin}" -H "Access-Control-Request-Method: POST" "${target}" -o /dev/null`);
      if (credentials) {
        lines.push(`# Credential test (with cookie)`);
        lines.push(`curl -I -s -D - -H "Origin: ${origin}" -H "Cookie: session=bad" "${target}" -o /dev/null`);
      }
      return lines.join('\n');
    };

    p.generatePoCMarkdown = (target, findings, score) => {
      let md = `# HeaderSleuth++ Report\n\n**Target:** ${target}\n**Score:** ${score}/100\n\n## Findings\n\n`;
      (findings || []).forEach(f => {
        md += `- **${f.title}** (severity ${f.sev}): ${f.desc}\n`;
      });

      md += `\n## Repro (examples)\n\n### Basic headers\n\`\`\`bash\n${p.generateCurlBasic(target)}\`\`\`\n\n### CORS test example\n\`\`\`bash\n${p.generateCORSpoC(target)}\`\`\`\n\n*Generated by HeaderSleuth++ ${HS.VERSION}*\n`;
      return md;
    };

    p.generateBurpPoC = (target, finding) => {
      // generate a Burp-friendly curl-like snippet (not actual Burp file)
      return `# Burp-like PoC snippet\n# Target: ${target}\n# Finding: ${finding.title}\n\nGET / HTTP/1.1\nHost: ${new URL(target).host}\nUser-Agent: Mozilla/5.0\nAccept: */*\nOrigin: https://evil.example.com\n\n# Repeat in Burp repeater for interactive verification\n`;
    };

    return p;
  })();

  /**************************************************************************
   * Diff engine (deep, recursive, fuzzy)
   **************************************************************************/
  HS.diff = (() => {
    const D = {};

    // normalize header keys and flatten
    D.flatten = (parsed) => {
      const map = {};
      if (!parsed || !parsed.headers) return map;
      Object.keys(parsed.headers).forEach(k => {
        map[k.toLowerCase()] = parsed.headers[k].join(' | ');
      });
      if (parsed.statusLine) map['_status'] = parsed.statusLine;
      return map;
    };

    D.keysUnion = (a, b) => {
      const set = new Set();
      Object.keys(a || {}).forEach(k => set.add(k));
      Object.keys(b || {}).forEach(k => set.add(k));
      return Array.from(set).sort();
    };

    D.diff = (pa, pb) => {
      const a = D.flatten(pa), b = D.flatten(pb);
      const keys = D.keysUnion(a, b);
      const rows = keys.map(k => {
        const va = a[k] || '';
        const vb = b[k] || '';
        return { header: k, a: va, b: vb, equal: va === vb };
      });
      return rows;
    };

    D.significantChanges = (rows) => {
      // return rows where presence or security-relevant values change
      return rows.filter(r => {
        if (!r.equal) {
          // further heuristics: HSTS change, CSP loosening, cookies changed
          if (r.header === 'strict-transport-security' || r.header === 'content-security-policy' || r.header.startsWith('set-cookie') || r.header.startsWith('access-control-allow')) return true;
          // any difference > trivial
          return true;
        }
        return false;
      });
    };

    return D;
  })();

  /**************************************************************************
   * Pattern search module
   **************************************************************************/
  HS.pattern = (() => {
    const P = {};

    P.search = (parsed, patterns) => {
      patterns = patterns || [];
      const hits = [];
      const headers = parsed.headers || {};
      Object.keys(headers).forEach(k => {
        (headers[k] || []).forEach(v => {
          patterns.forEach(pat => {
            try {
              const re = new RegExp(pat, 'i');
              if (re.test(v)) hits.push({ header: k, value: v, pattern: pat });
            } catch (e) {
              // invalid regex — fallback to substring
              if ((v || '').toLowerCase().indexOf(pat.toLowerCase()) !== -1) hits.push({ header: k, value: v, pattern: pat });
            }
          });
        });
      });
      return hits;
    };

    return P;
  })();

  /**************************************************************************
   * Snapshot manager (localStorage)
   **************************************************************************/
  HS.snap = (() => {
    const S = {};
    S.KEY_PREFIX = 'hs_snap_';

    S.save = (name, payload) => {
      const key = S.KEY_PREFIX + (name || HS.utils.now());
      try {
        localStorage.setItem(key, JSON.stringify({ ts: HS.utils.now(), payload }));
        return { ok: true, key };
      } catch (e) {
        return { ok: false, err: e.message || String(e) };
      }
    };

    S.list = () => {
      const out = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(S.KEY_PREFIX)) {
          try {
            out.push({ key: k, item: JSON.parse(localStorage.getItem(k)) });
          } catch (e) { /* skip */ }
        }
      }
      // newest first
      out.sort((a, b) => (b.item && b.item.ts || '').localeCompare(a.item && a.item.ts || ''));
      return out;
    };

    S.load = (key) => {
      try {
        const raw = localStorage.getItem(key);
        return raw ? JSON.parse(raw).payload : null;
      } catch (e) { return null; }
    };

    S.remove = (key) => {
      try { localStorage.removeItem(key); return true; } catch (e) { return false; }
    };

    return S;
  })();

  /**************************************************************************
   * UI Renderer factory (modular rendering functions)
   **************************************************************************/
  HS.ui = (() => {
    const UI = {};

    // binding convenience
    UI.el = (id) => HS.utils.$(id);

    UI.renderFindings = (containerId, findings) => {
      const el = UI.el(containerId);
      if (!el) return;
      if (!findings || findings.length === 0) { el.innerHTML = '<p>No findings.</p>'; return; }
      const pieces = findings.map(f => {
        const cls = f.sev >= 8 ? 'high' : (f.sev >= 5 ? 'medium' : (f.sev > 0 ? 'low' : 'ok'));
        const s = `<div class="finding ${cls}"><h4>${HS.utils.safeText(f.title)} <small>(${f.sev})</small></h4><p>${HS.utils.safeText(f.desc)}</p><div class="f-actions"><button class="btn-poc" data-id="${HS.utils.slug(f.id)}">PoC</button> <button class="btn-copy" data-t="${HS.utils.safeText(f.desc)}">Copy</button></div></div>`;
        return s;
      });
      el.innerHTML = pieces.join('\n');
      // wire up PoC & copy buttons delegation
      el.querySelectorAll('.btn-poc').forEach(b => {
        b.onclick = (ev) => {
          const id = ev.currentTarget.getAttribute('data-id');
          const f = findings.find(x => HS.utils.slug(x.id) === id);
          if (f) {
            const t = HS.ui.el('target') ? HS.ui.el('target').value : '[TARGET]';
            const md = HS.poc.generatePoCMarkdown(t, [f], HS.scorer.computeScore(findings));
            HS.ui.el('poc').textContent = md;
            alert('PoC generated in PoC panel (copy/download).');
          }
        };
      });
      el.querySelectorAll('.btn-copy').forEach(b => {
        b.onclick = async (ev) => {
          const t = ev.currentTarget.getAttribute('data-t') || '';
          const ok = await HS.utils.copyToClipboard(t);
          if (ok) alert('Copied to clipboard'); else alert('Copy failed — check permissions');
        };
      });
    };

    UI.renderCurlOutput = (text) => {
      const el = UI.el('curlOutput');
      if (el) el.textContent = text || '';
    };

    UI.renderAnalysis = (containerId, parsed) => {
      const el = UI.el(containerId);
      if (!el) return;
      if (!parsed || (!parsed.headers && !parsed.statusLine)) { el.innerHTML = '<p>No parsed data.</p>'; return; }
      let html = '';
      if (parsed.statusLine) html += `<pre class="analysis-header">${HS.utils.safeText(parsed.statusLine)}</pre>`;
      html += '<table class="analysis-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
      Object.keys(parsed.headers).forEach(k => {
        (parsed.headers[k] || []).forEach(v => html += `<tr><td>${HS.utils.safeText(k)}</td><td><code>${HS.utils.safeText(v)}</code></td></tr>`);
      });
      html += '</tbody></table>';
      el.innerHTML = html;
    };

    UI.renderDiff = (containerId, rows) => {
      const el = UI.el(containerId);
      if (!el) return;
      if (!Array.isArray(rows)) { el.innerHTML = '<p>No diff data</p>'; return; }
      let html = '<table class="diff-table"><thead><tr><th>Header</th><th>A</th><th>B</th></tr></thead><tbody>';
      rows.forEach(r => {
        html += `<tr class="${r.equal ? 'same' : 'diff'}"><td>${HS.utils.safeText(r.header)}</td><td><code>${HS.utils.safeText(r.a)}</code></td><td><code>${HS.utils.safeText(r.b)}</code></td></tr>`;
      });
      html += '</tbody></table>';
      el.innerHTML = html;
    };

    UI.renderSnapshots = (containerId) => {
      const el = UI.el(containerId);
      if (!el) return;
      const list = HS.snap.list();
      if (!list.length) { el.innerHTML = '<p>No snapshots saved</p>'; return; }
      const nodes = list.map(item => {
        const k = item.key;
        const ts = item.item && item.item.ts ? item.item.ts : '';
        return `<div class="snapitem"><div><strong>${HS.utils.safeText(k)}</strong><div class="muted">ts: ${HS.utils.safeText(ts)}</div></div><div class="snap-actions"><button data-k="${HS.utils.safeText(k)}" class="snap-load">Load</button> <button data-k="${HS.utils.safeText(k)}" class="snap-del">Delete</button></div></div>`;
      }).join('\n');
      el.innerHTML = nodes;
      // bind
      el.querySelectorAll('.snap-load').forEach(b => {
        b.onclick = (ev) => {
          const k = ev.currentTarget.getAttribute('data-k');
          const payload = HS.snap.load(k);
          if (!payload) { alert('Failed to load snapshot'); return; }
          // payload assumed to be { parsedA, parsedB, meta }
          if (payload.parsedA) HS.ui.el('pasteA').value = HS.parser.headersToString(payload.parsedA);
          if (payload.parsedB) HS.ui.el('pasteB').value = HS.parser.headersToString(payload.parsedB);
          alert('Snapshot loaded into paste boxes (A/B).');
        };
      });
      el.querySelectorAll('.snap-del').forEach(b => {
        b.onclick = (ev) => {
          const k = ev.currentTarget.getAttribute('data-k');
          if (confirm(`Delete snapshot ${k}?`)) { HS.snap.remove(k); UI.renderSnapshots(containerId); }
        };
      });
    };

    UI.renderScore = (containerId, score) => {
      const el = UI.el(containerId);
      if (!el) return;
      const color = HS.scorer.scoreColor(score);
      el.innerHTML = `<div class="score-pill ${color}">Security score: <strong>${score}/100</strong></div>`;
    };

    return UI;
  })();

  /**************************************************************************
   * Orchestration pipeline: run analysis for a parsed header block
   **************************************************************************/
  HS.pipeline = (() => {
    const pipe = {};

    pipe.analyzeParsed = (parsed) => {
      // gather findings from detectors
      const canonical = HS.parser.canonicalHeaderMap(parsed);
      const findings = [];
      // Phase1 basics (HSTS/CSP etc) reuse detectors
      // HSTS
      if (!canonical['strict-transport-security']) findings.push({ id: 'hsts-missing', title: 'HSTS missing', sev: 9, desc: 'Strict-Transport-Security header absent' });
      else {
        const v = canonical['strict-transport-security'];
        const m = v.match(/max-age=(\d+)/);
        const age = m ? parseInt(m[1], 10) : 0;
        if (!age) findings.push({ id: 'hsts-invalid', title: 'HSTS invalid', sev: 6, desc: `HSTS header present but max-age not set correctly: ${v}` });
        else if (age < 15768000) findings.push({ id: 'hsts-short', title: 'HSTS too short', sev: 5, desc: `HSTS max-age ${age} (< 6 months)` });
        else findings.push({ id: 'hsts-good', title: 'HSTS OK', sev: 0, desc: `HSTS ${HS.utils.safeText(v)}` });
      }

      // CSP
      if (!canonical['content-security-policy']) findings.push({ id: 'csp-missing', title: 'CSP missing', sev: 8, desc: 'Content-Security-Policy absent' });
      else {
        const cspS = canonical['content-security-policy'];
        const cspRes = HS.detectors.cspRiskScore(cspS);
        if (cspRes.score < 60) findings.push({ id: 'csp-risk', title: 'CSP weak / risky', sev: 8, desc: `CSP risky: score ${cspRes.score}, ${cspRes.notes.join(',')}` });
        else findings.push({ id: 'csp-good', title: 'CSP present', sev: 0, desc: `CSP: ${HS.utils.safeText(cspS)}` });
        // bypass hints
        const hints = HS.detectors.cspBypassHints(HS.detectors.parseCSP(cspS));
        hints.forEach((h, idx) => findings.push({ id: `csp-hint-${idx}`, title: 'CSP hint', sev: 4, desc: h }));
      }

      // X-Frame & content type & referrer
      if (!canonical['x-frame-options'] && !(canonical['content-security-policy'] && /frame-ancestors/i.test(canonical['content-security-policy']))) findings.push({ id: 'clickjacking', title: 'Clickjacking defenses missing', sev: 7, desc: 'No X-Frame-Options or CSP frame-ancestors' });
      if (!canonical['x-content-type-options']) findings.push({ id: 'xcto-missing', title: 'X-Content-Type-Options missing', sev: 5, desc: 'Add header X-Content-Type-Options: nosniff' });
      if (!canonical['referrer-policy']) findings.push({ id: 'referrer-missing', title: 'Referrer-Policy missing', sev: 3, desc: 'Add Referrer-Policy' });

      // CORS advanced
      const corsFindings = HS.detectors.analyzeCORS(parsed.headers);
      corsFindings.forEach(c => findings.push(c));

      // Cookies
      const cookieFindings = HS.detectors.analyzeCookies(parsed.headers);
      cookieFindings.forEach(c => findings.push(c));

      // fingerprint
      const fp = HS.detectors.fingerprint(parsed.headers);
      fp.forEach(f => findings.push(f));

      // SRI not here (needs tag string separate)

      // pattern search (if user specified patterns exist in UI, optional)
      const patternInput = (HS.utils.$('patternSearch') ? HS.utils.$('patternSearch').value : '') || '';
      if (patternInput.trim()) {
        const pats = patternInput.split(',').map(x => x.trim()).filter(Boolean);
        const hits = HS.pattern.search(parsed, pats);
        hits.forEach((h, idx) => findings.push({ id: `pattern-${idx}`, title: `Pattern hit: ${h.pattern}`, sev: 2, desc: `${h.header}: ${h.value}` }));
      }

      // merge & dedupe by id (basic)
      const dedup = {};
      findings.forEach(f => { dedup[f.id] = dedup[f.id] || f; });
      const final = Object.keys(dedup).map(k => dedup[k]);

      // compute score
      const score = HS.scorer.computeScore(final);

      return { parsed, findings: final, score, canonical };
    };

    return pipe;
  })();

  /**************************************************************************
   * Event wiring & bootstrapping
   **************************************************************************/
  HS.bind = (() => {
    const B = {};

    B.start = () => {
      HS.domReady(() => {
        log('HeaderSleuth++ initializing', HS.VERSION);
        // UI element shortcuts
        const get = HS.utils.$;

        // ensure required elements exist; if not, create minimal ones so script doesn't fail
        const requiredIDs = ['target', 'origins', 'cred', 'preflight', 'genCurl', 'copyCurl', 'downloadCurl', 'curlOutput',
          'pasteA', 'pasteB', 'analyzeA', 'analyzeB', 'analysis', 'findings', 'poc', 'diffAB', 'exportMD', 'listSnaps', 'snapList', 'patternSearch'];
        requiredIDs.forEach(id => {
          if (!get(id)) {
            // create hidden inputs or panels if missing (non-intrusive)
            log(`UI element ${id} not found; creating placeholder`);
            const el = document.createElement('div');
            el.style.display = 'none';
            el.id = id;
            document.body.appendChild(el);
          }
        });

        // main bindings
        const btnGen = get('genCurl');
        if (btnGen) btnGen.addEventListener('click', () => {
          const tRaw = get('target').value || '';
          const t = HS.parser.normalizeTarget(tRaw).raw;
          const origins = (get('origins').value || '').split(',').map(x => x.trim()).filter(Boolean);
          const cred = get('cred') ? get('cred').checked : false;
          const pre = get('preflight') ? get('preflight').checked : false;
          const curl = HS.poc.generateCurlBasic(t) + '\n' + HS.poc.generateCORSpoC(t, origins[0] || 'https://evil.example.com', pre, cred);
          HS.ui.renderCurlOutput(curl);
        });

        const btnCopy = get('copyCurl');
        if (btnCopy) btnCopy.addEventListener('click', async () => {
          const txt = get('curlOutput').textContent || '';
          if (!txt) return alert('No curl output present');
          const ok = await HS.utils.copyToClipboard(txt);
          alert(ok ? 'Curl commands copied to clipboard' : 'Copy failed (check permissions)');
        });

        const btnDL = get('downloadCurl');
        if (btnDL) btnDL.addEventListener('click', () => {
          const txt = get('curlOutput').textContent || '';
          if (!txt) return alert('No curl commands to download');
          HS.utils.download('cors-tests.sh', txt);
        });

        // analyze A
        const btnA = get('analyzeA');
        if (btnA) btnA.addEventListener('click', () => {
          const raw = (get('pasteA').value || '');
          if (!raw.trim()) return alert('Paste headers into A first');
          const parsed = HS.parser.parseRawHeaders(raw);
          const r = HS.pipeline.analyzeParsed(parsed);
          HS.ui.renderAnalysis('analysis', parsed);
          HS.ui.renderFindings('findings', r.findings);
          HS.ui.renderScore('poc', r.score); // reuse poc area to show score (or separately)
          // show in PoC area a short md
          const md = HS.poc.generatePoCMarkdown(HS.parser.normalizeTarget(get('target').value).raw || '[TARGET]', r.findings, r.score);
          HS.ui.el('poc').textContent = md;
        });

        // analyze B
        const btnB = get('analyzeB');
        if (btnB) btnB.addEventListener('click', () => {
          const raw = (get('pasteB').value || '');
          if (!raw.trim()) return alert('Paste headers into B first');
          const parsed = HS.parser.parseRawHeaders(raw);
          const r = HS.pipeline.analyzeParsed(parsed);
          // include both analyses in UI; keep findings aggregated (append)
          HS.ui.renderAnalysis('analysis', parsed);
          HS.ui.renderFindings('findings', r.findings);
          HS.ui.el('poc').textContent = HS.poc.generatePoCMarkdown(HS.parser.normalizeTarget(get('target').value).raw || '[TARGET]', r.findings, r.score);
        });

        // diff A/B
        const btnDiff = get('diffAB');
        if (btnDiff) btnDiff.addEventListener('click', () => {
          const pa = HS.parser.parseRawHeaders(get('pasteA').value || '');
          const pb = HS.parser.parseRawHeaders(get('pasteB').value || '');
          const rows = HS.diff.diff(pa, pb);
          HS.ui.renderDiff('findings', rows);
        });

        // export MD (PoC)
        const btnExport = get('exportMD');
        if (btnExport) btnExport.addEventListener('click', () => {
          const content = (get('poc').textContent || '# HeaderSleuth++ PoC') + `\n\nGenerated: ${HS.utils.now()}`;
          HS.utils.download('headersleuth-poc.md', content, 'text/markdown');
        });

        // snapshots
        const btnList = get('listSnaps');
        if (btnList) btnList.addEventListener('click', () => {
          HS.ui.renderSnapshots('snapList');
        });

        // save snapshot for A
        const saveA = get('saveA');
        if (saveA) saveA.addEventListener('click', () => {
          const payload = { parsedA: HS.parser.parseRawHeaders(get('pasteA').value || ''), parsedB: HS.parser.parseRawHeaders(get('pasteB').value || ''), meta: { target: get('target').value || '', ts: HS.utils.now() } };
          const res = HS.snap.save('snap-' + (get('target').value ? HS.utils.slug(get('target').value) : 'manual') + '-' + new Date().getTime(), payload);
          if (res.ok) alert('Snapshot saved: ' + res.key);
          else alert('Snapshot save failed: ' + res.err);
        });

        // save snapshot for B
        const saveB = get('saveB');
        if (saveB) saveB.addEventListener('click', () => {
          const payload = { parsedA: HS.parser.parseRawHeaders(get('pasteA').value || ''), parsedB: HS.parser.parseRawHeaders(get('pasteB').value || ''), meta: { target: get('target').value || '', ts: HS.utils.now() } };
          const res = HS.snap.save('snap-' + (get('target').value ? HS.utils.slug(get('target').value) : 'manual') + '-' + new Date().getTime(), payload);
          if (res.ok) alert('Snapshot saved: ' + res.key);
          else alert('Snapshot save failed: ' + res.err);
        });

        // pattern search wiring (optional element patternSearch)
        const patEl = get('patternSearch');
        if (patEl) {
          patEl.addEventListener('change', () => {
            // run pattern search on current pasteA
            const parsed = HS.parser.parseRawHeaders(get('pasteA').value || '');
            const patterns = (patEl.value || '').split(',').map(x => x.trim()).filter(Boolean);
            if (!patterns.length) return;
            const hits = HS.pattern.search(parsed, patterns);
            if (hits.length) {
              const msgs = hits.map(h => `${h.header}: ${h.value}`).join('\n');
              alert(`Pattern search hits:\n${msgs}`);
            } else {
              alert('No pattern hits');
            }
          });
        }

        // quick auto-load sample (developer convenience) if UI lacks content
        if (!get('pasteA').value && !get('pasteB').value && HS.DEBUG) {
          get('pasteA').value = `HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval' https://cdn.example.com\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\nSet-Cookie: sessionid=abcd1234; Path=/; Expires=Wed, 09 Jun 2026 10:18:14 GMT; HttpOnly\nServer: nginx/1.18.0\n`;
        }

        log('HeaderSleuth++ bindings attached');
      });
    };

    return B;
  })();

  /**************************************************************************
   * Initialize
   **************************************************************************/
  HS.domReady(() => {
    HS.bind.start();
    log('HeaderSleuth++ ready', HS.VERSION);
  });

  // Expose for debugging in console if allowed
  if (typeof window !== 'undefined') window.HeaderSleuth = HS;

})(); // end of massive IIFE
