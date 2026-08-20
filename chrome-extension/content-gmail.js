const API = 'https://phishing-url-detector-je19.onrender.com';

let bannerVisible = false;

function getPlatform() {
  const host = window.location.hostname;
  if (host.includes('mail.google.com')) return 'gmail';
  if (host.includes('outlook.live.com') || host.includes('outlook.office')) return 'outlook';
  if (host.includes('mail.yahoo.com')) return 'yahoo';
  return 'unknown';
}

function getEmailBody() {
  const platform = getPlatform();

  if (platform === 'gmail') {
    const el = document.querySelector('.a3s.aiL, .a3s');
    return el ? el.innerText : '';
  }

  if (platform === 'outlook') {
    const selectors = [
      '[aria-label="Message body"]',
      '.ReadingPaneContent',
      '[role="document"]',
      '.scrollable-region-content'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 20) return el.innerText;
    }
    return '';
  }

  if (platform === 'yahoo') {
    const selectors = [
      '.msg-body',
      '[data-test-id="message-view-body"]',
      '.ReadableMessageBody'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 20) return el.innerText;
    }
    return '';
  }

  return '';
}

const scannedLinkEls = new WeakSet();
const linkCheckCache = new Map(); // url -> { level, score }

function getEmailBodyElement() {
  const platform = getPlatform();
  if (platform === 'gmail') {
    return document.querySelector('.a3s.aiL, .a3s');
  }
  if (platform === 'outlook') {
    const selectors = [
      '[aria-label="Message body"]',
      '.ReadingPaneContent',
      '[role="document"]',
      '.scrollable-region-content'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 20) return el;
    }
    return null;
  }
  if (platform === 'yahoo') {
    const selectors = [
      '.msg-body',
      '[data-test-id="message-view-body"]',
      '.ReadableMessageBody'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 20) return el;
    }
    return null;
  }
  return null;
}

function addLinkWarningIcon(linkEl, level, score) {
  const next = linkEl.nextSibling;
  if (next && next.classList && next.classList.contains('phish-link-flag')) return;

  const colors = { MEDIUM: '#fbbf24', HIGH: '#f87171' };

  const icon = document.createElement('span');
  icon.className = 'phish-link-flag';
  icon.title = `⚠️ ${level} RISK (${score}/100) — auto-scanned by Alurtra`;
  icon.textContent = ' ⚠️';
  icon.style.cssText = `
    color: ${colors[level] || '#f87171'};
    font-size: 13px;
    cursor: default;
    user-select: none;
    display: inline;
  `;
  linkEl.insertAdjacentElement('afterend', icon);
}

let scanQueue = [];
let activeWorkers = 0;
const MAX_CONCURRENT = 5;   // check 5 links at once
const MAX_LINKS_PER_EMAIL = 25; // cap so huge emails don't eat the whole rate-limit budget

async function checkLink(linkEl, url) {
  try {
    let data = linkCheckCache.get(url);
    if (!data) {
      const res = await fetch(`${API}/check?url=${encodeURIComponent(url)}`);
      if (!res.ok) return; // rate-limited or errored, skip silently rather than show bad data
      data = await res.json();
      linkCheckCache.set(url, data);
    }

    const level = data.riskLevel
      ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
      : 'LOW';

    if (level === 'MEDIUM' || level === 'HIGH') {
      addLinkWarningIcon(linkEl, level, data.riskScore);
    }
  } catch (e) {}
}

function pumpQueue() {
  while (activeWorkers < MAX_CONCURRENT && scanQueue.length > 0) {
    const { linkEl, url } = scanQueue.shift();
    activeWorkers++;
    checkLink(linkEl, url).finally(() => {
      activeWorkers--;
      pumpQueue();
    });
  }
}

function scanLinksInEmail() {
  const body = getEmailBodyElement();
  if (!body) return;
  const links = body.querySelectorAll('a[href^="http"]');
  let queued = 0;
  for (const link of links) {
    if (queued >= MAX_LINKS_PER_EMAIL) break;
    if (scannedLinkEls.has(link)) continue;
    if (!link.href) continue;
    scannedLinkEls.add(link);
    scanQueue.push({ linkEl: link, url: link.href });
    queued++;
  }
  pumpQueue();
}

function removeBanner() {
  const old = document.getElementById('phish-banner');
  if (old) old.remove();
  bannerVisible = false;
  const btn = document.getElementById('phish-toggle-btn');
  if (btn) {
    btn.innerHTML = '<img src="' + chrome.runtime.getURL('icons/logo4.png') + '" style="height:16px;width:16px;vertical-align:middle;margin-right:6px;"> Scan Email';
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
        btn.innerHTML = '<img src="' + chrome.runtime.getURL('icons/logo4.png') + '" style="height:16px;width:16px;vertical-align:middle;margin-right:6px;"> Scan Email';
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
  const warningsBlock = warnings ? `<div style="font-size:10px;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Warnings</div><ul style="padding:0;margin:0;">${warnings}</ul>` : '';

  const cleanAi = data.aiAnalysis ? data.aiAnalysis.replace(/\*\*(.*?)\*\*/g, '$1').replace(/\*(.*?)\*/g, '$1') : null;
  const aiBlock = cleanAi
    ? `<div style="margin-top:10px;padding:10px;background:rgba(0,0,0,0.3);border-radius:8px;border-left:3px solid #4f46e5;">
        <div style="font-size:10px;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">AI Analysis</div>
        <div style="font-size:12px;color:#ccc;line-height:1.5;">${cleanAi}</div>
       </div>`
    : '';

  banner.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <span style="color:${c.text};font-weight:700;font-size:14px;"><img src="${chrome.runtime.getURL('icons/logo4.png')}" style="height:14px;width:14px;vertical-align:middle;margin-right:6px;"> ${level} RISK — ${data.riskScore}/100</span>
      <span id="phish-close" style="cursor:pointer;color:#888;font-size:18px;margin-left:12px;line-height:1;">✕</span>
    </div>
    ${warningsBlock}
    ${aiBlock}
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
    if (!res.ok) {
      alert(res.status === 429
        ? 'Too many requests right now — please wait a minute and try again.'
        : 'Could not complete scan. Please try again.');
      return;
    }
    const data = await res.json();
    showBanner(data);
  } catch (e) {
    alert('Could not reach Alurtra backend.');
  } finally {
    const btn = document.getElementById('phish-toggle-btn');
    if (btn) btn.disabled = false;
  }
}

function createToggleButton() {
  if (document.getElementById('phish-toggle-btn')) return;

  const btn = document.createElement('button');
  btn.id = 'phish-toggle-btn';
  btn.innerHTML = '<img src="' + chrome.runtime.getURL('icons/logo4.png') + '" style="height:16px;width:16px;vertical-align:middle;margin-right:6px;"> Scan Email';
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

createToggleButton();
scanLinksInEmail();

const observer = new MutationObserver(() => {
  createToggleButton();
  scanLinksInEmail();
  if (bannerVisible) {
    const emailBody = getEmailBody();
    if (!emailBody) removeBanner();
  }
});
observer.observe(document.body, { childList: true, subtree: true });
