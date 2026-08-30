const API = 'https://phishing-url-detector-6462.onrender.com';

// Cache results so we don't call the API for the same URL twice
const cache = {};

async function checkUrl(url) {
  if (cache[url] !== undefined) return cache[url];
  try {
    const res = await fetch(`${API}/check?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    const level = data.riskLevel
      ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
      : 'LOW';
    cache[url] = { level, score: data.riskScore, warnings: data.warnings || [], aiAnalysis: data.aiAnalysis || null, communityReports: data.communityReports || 0 };
    return cache[url];
  } catch (e) {
    cache[url] = null;
    return null;
  }
}

function showWarningPage(url, result) {
  // Block navigation and show a full-page warning overlay
  const overlay = document.createElement('div');
  overlay.id = 'phish-intercept-overlay';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    background: #0a0a14;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: Arial, sans-serif;
    overflow-y: auto;
    padding: 20px;
  `;

  const colors = {
    HIGH:   { border: '#f87171', badge: '#7f1d1d', text: '#f87171' },
    MEDIUM: { border: '#fbbf24', badge: '#713f12', text: '#fbbf24' },
  };
  const c = colors[result.level] || colors.MEDIUM;

  const warnings = result.warnings.slice(0, 4).map(w =>
    `<li style="margin-bottom:8px;color:#ccc;font-size:14px;">${w}</li>`
  ).join('');

  const community = result.communityReports > 0
    ? `<div style="margin-top:12px;padding:10px;background:#1e1e32;border-radius:8px;color:#fbbf24;font-size:13px;">🍁 ${result.communityReports} Canadian${result.communityReports === 1 ? '' : 's'} reported this as a scam</div>`
    : '';

  const ai = result.aiAnalysis
    ? `<div style="margin-top:12px;padding:12px;background:#0d0d1a;border-radius:8px;border-left:3px solid #4f46e5;"><div style="font-size:11px;color:#555;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">AI Analysis</div><div style="font-size:13px;color:#ccc;line-height:1.5;">${result.aiAnalysis}</div></div>`
    : '';

  overlay.innerHTML = `
    <div style="max-width:520px;width:90%;background:#13131f;border:2px solid ${c.border};border-radius:16px;padding:36px;box-shadow:0 20px 60px rgba(0,0,0,0.8);margin:auto;">
      <div style="font-size:48px;text-align:center;margin-bottom:16px;">⚠️</div>
      <h1 style="color:${c.text};font-size:22px;font-weight:800;text-align:center;margin-bottom:8px;">
        ${result.level === 'HIGH' ? 'Dangerous Link Blocked' : 'Suspicious Link Warning'}
      </h1>
      <p style="color:#888;font-size:13px;text-align:center;margin-bottom:20px;word-break:break-all;">${url}</p>

      <div style="background:#0d0d1a;border-radius:10px;padding:14px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <span style="color:#555;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;">Risk Score</span>
          <span style="color:${c.text};font-weight:700;">${result.score}/100</span>
        </div>
        <ul style="padding-left:16px;margin:0;">${warnings}</ul>
        ${community}
        ${ai}
      </div>

      <div style="display:flex;gap:10px;">
        <button id="phish-go-back" style="flex:1;padding:14px;background:#1e1e2e;border:1px solid #2a2a40;border-radius:10px;color:#fff;font-size:14px;font-weight:700;cursor:pointer;">
          ← Go Back (Safe)
        </button>
        <button id="phish-continue" style="flex:1;padding:14px;background:#7f1d1d;border:none;border-radius:10px;color:#f87171;font-size:14px;font-weight:600;cursor:pointer;">
          Continue Anyway
        </button>
      </div>
      <p style="color:#333;font-size:11px;text-align:center;margin-top:12px;">Powered by Alurtra</p>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById('phish-go-back').addEventListener('click', () => {
    overlay.remove();
    history.back();
  });

  document.getElementById('phish-continue').addEventListener('click', () => {
    overlay.remove();
    window.location.href = url;
  });
}

// Intercept all link clicks
document.addEventListener('click', async (e) => {
  const link = e.target.closest('a[href]');
  if (!link) return;

  const href = link.href;
  if (!href || !href.startsWith('http')) return;

  // Don't intercept links on the same domain
  if (href.startsWith(window.location.origin)) return;

  // Don't intercept links to known safe domains
  const safeDomains = ['google.com', 'youtube.com', 'github.com', 'wikipedia.org'];
  if (safeDomains.some(d => href.includes(d))) return;

  e.preventDefault();
  e.stopPropagation();

  const result = await checkUrl(href);
  if (!result) {
    window.location.href = href;
    return;
  }

  if (result.level === 'HIGH' || result.level === 'MEDIUM') {
    showWarningPage(href, result);
  } else {
    window.location.href = href;
  }
}, true);
