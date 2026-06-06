const API = 'https://phishing-url-detector-je19.onrender.com';

let bannerVisible = false;

function getEmailBody() {
  const bodyEl = document.querySelector('.a3s.aiL, .a3s');
  return bodyEl ? bodyEl.innerText : '';
}

function removeBanner() {
  const old = document.getElementById('phish-banner');
  if (old) old.remove();
  bannerVisible = false;
  const btn = document.getElementById('phish-toggle-btn');
  if (btn) {
    btn.textContent = '🛡️ Scan Email';
    btn.style.background = '#4f46e5';
  }
}

function showBanner(data) {
  const existing = document.getElementById('phish-banner');
  if (existing) existing.remove();

  const level = data.riskLevel
    ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
    : 'LOW';

  if (level === 'LOW' && data.riskScore === 0) {
    const btn = document.getElementById('phish-toggle-btn');
    if (btn) {
      btn.textContent = '✅ Safe';
      btn.style.background = '#14532d';
    }
    setTimeout(() => {
      if (btn) {
        btn.textContent = '🛡️ Scan Email';
        btn.style.background = '#4f46e5';
      }
    }, 3000);
    return;
  }

  const colors = {
    LOW:    { bg: '#0a2a0a', border: '#4ade80', text: '#4ade80' },
    MEDIUM: { bg: '#3a2000', border: '#fbbf24', text: '#fbbf24' },
    HIGH:   { bg: '#3a0000', border: '#f87171', text: '#f87171' },
  };
  const c = colors[level];

  const banner = document.createElement('div');
  banner.id = 'phish-banner';
  banner.style.cssText = `
    position: fixed;
    top: 70px;
    right: 20px;
    z-index: 99999;
    background: ${c.bg};
    border: 2px solid ${c.border};
    border-radius: 12px;
    padding: 14px 18px;
    max-width: 340px;
    font-family: Arial, sans-serif;
    box-shadow: 0 4px 24px rgba(0,0,0,0.5);
  `;

  const warnings = (data.warnings || []).slice(0, 5).map(w =>
    `<li style="margin-bottom:5px;font-size:12px;color:#ccc;list-style:none;">${w}</li>`
  ).join('');

  banner.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <span style="color:${c.text};font-weight:700;font-size:14px;">🛡️ ${level} RISK — ${data.riskScore}/100</span>
      <span id="phish-close" style="cursor:pointer;color:#888;font-size:18px;margin-left:12px;line-height:1;">✕</span>
    </div>
    ${warnings ? '<ul style="padding:0;margin:0;">' + warnings + '</ul>' : ''}
  `;

  document.body.appendChild(banner);
  bannerVisible = true;

  document.getElementById('phish-close').addEventListener('click', removeBanner);

  const btn = document.getElementById('phish-toggle-btn');
  if (btn) {
    btn.textContent = '✕ Dismiss';
    btn.style.background = '#7f1d1d';
  }
}

async function scanEmail() {
  if (bannerVisible) {
    removeBanner();
    return;
  }

  const body = getEmailBody();
  if (!body) {
    alert('No email content found. Please open an email first.');
    return;
  }

  const btn = document.getElementById('phish-toggle-btn');
  if (btn) {
    btn.textContent = '⏳ Scanning...';
    btn.style.background = '#333';
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API}/check-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: body
    });
    const data = await res.json();
    showBanner(data);
  } catch (e) {
    alert('Could not reach Phishing Detector backend.');
  } finally {
    if (btn) btn.disabled = false;
  }
}

function createToggleButton() {
  if (document.getElementById('phish-toggle-btn')) return;

  const btn = document.createElement('button');
  btn.id = 'phish-toggle-btn';
  btn.textContent = '🛡️ Scan Email';
  btn.style.cssText = `
    position: fixed;
    bottom: 28px;
    right: 28px;
    z-index: 99999;
    background: #4f46e5;
    color: white;
    border: none;
    border-radius: 24px;
    padding: 12px 20px;
    font-size: 13px;
    font-weight: 700;
    font-family: Arial, sans-serif;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
    transition: background 0.2s;
  `;
  btn.addEventListener('click', scanEmail);
  document.body.appendChild(btn);
}

// Create button when Gmail loads
createToggleButton();

// Recreate button if Gmail navigates (SPA)
const observer = new MutationObserver(() => {
  createToggleButton();
  if (bannerVisible) {
    const emailBody = getEmailBody();
    if (!emailBody) removeBanner();
  }
});
observer.observe(document.body, { childList: true, subtree: true });
