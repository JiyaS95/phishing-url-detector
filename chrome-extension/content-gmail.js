// Runs on Gmail - detects open emails and shows a phishing warning banner

const API = 'https://phishing-url-detector-je19.onrender.com';

let lastCheckedBody = '';

function getEmailBody() {
  // Gmail renders email body in .a3s or [data-message-id] divs
  const bodyEl = document.querySelector('.a3s.aiL, .a3s');
  return bodyEl ? bodyEl.innerText : '';
}

function removeBanner() {
  const old = document.getElementById('phish-banner');
  if (old) old.remove();
}

function showBanner(data) {
  removeBanner();
  const level = data.riskLevel
    ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
    : 'LOW';

  if (level === 'LOW' && data.riskScore === 0) return; // don't show banner for clean emails

  const colors = {
    LOW:    { bg: '#14532d', border: '#4ade80', text: '#4ade80' },
    MEDIUM: { bg: '#3a2000', border: '#fbbf24', text: '#fbbf24' },
    HIGH:   { bg: '#3a0000', border: '#f87171', text: '#f87171' },
  };
  const c = colors[level];

  const banner = document.createElement('div');
  banner.id = 'phish-banner';
  banner.style.cssText = `
    position: fixed;
    top: 60px;
    right: 20px;
    z-index: 99999;
    background: ${c.bg};
    border: 2px solid ${c.border};
    border-radius: 10px;
    padding: 12px 16px;
    max-width: 320px;
    font-family: 'Segoe UI', sans-serif;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  `;

  const warnings = (data.warnings || []).slice(0, 4).map(w =>
    `<li style="margin-bottom:4px;font-size:12px;color:#ccc;">${w}</li>`
  ).join('');

  banner.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span style="color:${c.text};font-weight:700;font-size:14px;">🛡️ Phishing Detector: ${level} RISK</span>
      <span id="phish-close" style="cursor:pointer;color:#888;font-size:16px;margin-left:12px;">✕</span>
    </div>
    <div style="color:#aaa;font-size:12px;margin-bottom:6px;">Score: ${data.riskScore}/100</div>
    ${warnings ? '<ul style="padding-left:16px;">' + warnings + '</ul>' : ''}
  `;

  document.body.appendChild(banner);
  document.getElementById('phish-close').addEventListener('click', removeBanner);
}

async function analyzeCurrentEmail() {
  const body = getEmailBody();
  if (!body || body === lastCheckedBody) return;
  lastCheckedBody = body;

  try {
    const res = await fetch(`${API}/check-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: body
    });
    const data = await res.json();
    showBanner(data);
  } catch (e) {
    // Backend unreachable, fail silently
  }
}

// Watch for Gmail navigation (opening emails)
const observer = new MutationObserver(() => {
  analyzeCurrentEmail();
});
observer.observe(document.body, { childList: true, subtree: true });
