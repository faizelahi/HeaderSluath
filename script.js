// HeaderSleuth - client-only logic
// No requests are made from the page. It only generates curl commands and parses pasted headers.

function normalizeTarget(raw) {
  if (!raw) return '';
  raw = raw.trim();
  // Add scheme if absent (default to https)
  if (!/^https?:\/\//i.test(raw)) {
    raw = 'https://' + raw;
  }
  return raw.replace(/\/+$/,''); // strip trailing slash
}

function genBasicCurl(t) {
  return [
    `# Basic HEAD request (headers only)`,
    `curl -I -s -D - "${t}" -o /dev/null`,
    ``,
    `# Full GET (follow redirects, show headers)`,
    `curl -L -s -D - "${t}" -o /dev/null`
  ].join('\n');
}

function genCORSCommands(t) {
  return [
    `# CORS tests — run these locally and inspect Access-Control-Allow-* headers`,
    `curl -I -s -D - -H "Origin: https://evil.example.com" "${t}" -o /dev/null`,
    `curl -I -s -D - -H "Origin: null" "${t}" -o /dev/null`,
    `# If site returns Access-Control-Allow-Origin: * or echoes Origin, investigate further.`,
    ``
  ].join('\n');
}

function genCookieCommands(t) {
  return [
    `# Cookie security checks — look for Secure, HttpOnly, SameSite flags in Set-Cookie`,
    `curl -I -s -D - "${t}" -o /dev/null`,
    `# Or make a full GET to capture cookies set on body responses:`,
    `curl -L -s -D - "${t}" -o /dev/null`
  ].join('\n');
}

document.getElementById('genBasic').addEventListener('click', () => {
  const t = normalizeTarget(document.getElementById('target').value);
  document.getElementById('curlOutput').textContent = t ? genBasicCurl(t) : '# Enter a valid target first';
});
document.getElementById('genCORS').addEventListener('click', () => {
  const t = normalizeTarget(document.getElementById('target').value);
  document.getElementById('curlOutput').textContent = t ? genCORSCommands(t) : '# Enter a valid target first';
});
document.getElementById('genCookie').addEventListener('click', () => {
  const t = normalizeTarget(document.getElementById('target').value);
  document.getElementById('curlOutput').textContent = t ? genCookieCommands(t) : '# Enter a valid target first';
});

document.getElementById('clear').addEventListener('click', () => {
  document.getElementById('pasteHeaders').value = '';
  document.getElementById('analysis').innerHTML = '';
  document.getElementById('curlOutput').textContent = '';
});

function parseHeaders(raw) {
  const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const result = {};
  let statusLine = '';
  lines.forEach(line => {
    if (!line.includes(':')) {
      // maybe status line
      if (line.toUpperCase().startsWith('HTTP/')) statusLine = line;
      return;
    }
    const idx = line.indexOf(':');
    const name = line.slice(0, idx).trim();
    const val = line.slice(idx+1).trim();
    const key = name.toLowerCase();
    if (!result[key]) result[key] = [];
    result[key].push(val);
  });
  return { statusLine, headers: result };
}

function analyze(parsed) {
  const h = parsed.headers;
  const out = [];
  // Basic presence checks
  const checks = [
    { name: 'Strict-Transport-Security (HSTS)', key: 'strict-transport-security', good: !!h['strict-transport-security'] },
    { name: 'Content-Security-Policy (CSP)', key: 'content-security-policy', good: !!h['content-security-policy'] },
    { name: 'X-Frame-Options', key: 'x-frame-options', good: !!h['x-frame-options'] },
    { name: 'X-Content-Type-Options', key: 'x-content-type-options', good: !!h['x-content-type-options'] },
    { name: 'Referrer-Policy', key: 'referrer-policy', good: !!h['referrer-policy'] },
    { name: 'Permissions-Policy (Feature-Policy)', key: 'permissions-policy', good: !!h['permissions-policy'] || !!h['feature-policy'] },
  ];
  out.push('<ul>');
  checks.forEach(c => {
    if (c.good) out.push(`<li class="ok">✅ ${c.name} — present</li>`);
    else out.push(`<li class="warn">⚠️ ${c.name} — <strong>missing</strong></li>`);
  });
  out.push('</ul>');

  // CORS
  if (h['access-control-allow-origin']) {
    const val = h['access-control-allow-origin'].join(', ');
    out.push(`<p class="info">CORS: <code>Access-Control-Allow-Origin: ${escapeHtml(val)}</code></p>`);
    if (val.trim() === '*' && h['access-control-allow-credentials']) {
      out.push(`<p class="bad">❌ Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials is insecure.</p>`);
    }
    if (val.includes('${') || val.toLowerCase().includes('null')) {
      // just a weak heuristic
    }
  } else {
    out.push(`<p class="warn">⚠️ No Access-Control-Allow-Origin header seen — CORS may be defaulted to disallow requests from other origins.</p>`);
  }

  // CSP weakness heuristics
  if (h['content-security-policy']) {
    const csp = h['content-security-policy'].join(' ');
    if (/unsafe-inline|unsafe-eval|data:|blob:/i.test(csp)) {
      out.push(`<p class="bad">❌ CSP contains risky directives (unsafe-inline / unsafe-eval / data: / blob:). Review carefully.</p>`);
    } else {
      out.push(`<p class="ok">✅ CSP present and no obvious risky keywords detected.</p>`);
    }
  }

  // Cookies
  if (h['set-cookie']) {
    out.push('<h4>Set-Cookie analysis</h4>');
    h['set-cookie'].forEach(sc => {
      const flags = [];
      if (/;.*HttpOnly/i.test(sc)) flags.push('HttpOnly');
      if (/;.*Secure/i.test(sc)) flags.push('Secure');
      if (/;.*SameSite=/i.test(sc)) {
        const ss = sc.match(/;.*SameSite=([^;]+)/i);
        if (ss) flags.push('SameSite='+ss[1]);
      }
      if (!/;.*HttpOnly/i.test(sc)) out.push(`<p class="bad">❌ Cookie missing HttpOnly: <code>${escapeHtml(sc)}</code></p>`);
      if (!/;.*Secure/i.test(sc)) out.push(`<p class="bad">❌ Cookie missing Secure flag (cookie may be sent over HTTP): <code>${escapeHtml(sc)}</code></p>`);
      if (!/;.*SameSite=/i.test(sc)) out.push(`<p class="warn">⚠️ Cookie missing SameSite policy: <code>${escapeHtml(sc)}</code></p>`);
      if (flags.length) out.push(`<p class="info">Cookie flags detected: ${escapeHtml(flags.join(', '))}</p>`);
    });
  } else {
    out.push(`<p class="info">No Set-Cookie headers found in pasted response.</p>`);
  }

  // Additional notes
  out.push(`<h4>Quick tips</h4>`);
  out.push(`<ul><li>Run the generated <code>curl</code> tests (section 1) to confirm header behavior in different scenarios (Origin header, redirect flows).</li>`);
  out.push(`<li>For CORS testing, set a custom Origin header (see generated curl) and look for Access-Control-Allow-Origin and Access-Control-Allow-Credentials.</li>`);
  out.push(`<li>For detailed CSP checks, use a CSP evaluator in a sandbox environment.</li></ul>`);

  return out.join('\n');
}

function escapeHtml(s) {
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

document.getElementById('analyze').addEventListener('click', () => {
  const raw = document.getElementById('pasteHeaders').value;
  if (!raw.trim()) {
    document.getElementById('analysis').innerHTML = '<p class="warn">Paste headers first (from curl -I or devtools).</p>';
    return;
  }
  const parsed = parseHeaders(raw);
  const html = analyze(parsed);
  document.getElementById('analysis').innerHTML = html;
});
