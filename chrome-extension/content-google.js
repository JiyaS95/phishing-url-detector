const API = 'https://phishing-url-detector-je19.onrender.com';

function createBadge(level, score) {
  const colors = {
    LOW:    { bg: '#14532d', color: '#4ade80' },
    MEDIUM: { bg: '#713f12', color: '#fbbf24' },
    HIGH:   { bg: '#7f1d1d', color: '#f87171' },
  };
  const c = colors[level] || colors.LOW;

  // Use shadow DOM to fully isolate from Google's CSS
  const host = document.createElement('span');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = `
    <style>
      span {
        display: inline-block;
        margin-left: 12px;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 700;
        font-family: Arial, sans-serif;
        background: ${c.bg};
        color: ${c.color};
        vertical-align: middle;
        white-space: nowrap;
        writing-mode: horizontal-tb;
        direction: ltr;
        transform: none;
      }
    </style>
    <span>${level} ${score}/100</span>
  `;
  return host;
}

async function checkAndBadge(linkEl, url) {
  try {
    const res = await fetch(`${API}/check?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    const level = data.riskLevel
      ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
      : 'LOW';

    const badge = createBadge(level, data.riskScore);
    // Insert badge after the URL line (cite element), not inside the link
    // Insert badge after the cite (URL line), before the dots menu
    const parentDiv = linkEl.closest('div') || linkEl.parentElement;
    const cite = parentDiv.querySelector('cite');
    if (cite) {
      cite.after(badge);
    } else {
      linkEl.parentElement.appendChild(badge);
    }

    if (level === 'HIGH') {
      const block = linkEl.closest('div[data-hveid]') || linkEl.parentElement;
      if (block) {
        block.style.opacity = '0.4';
        block.style.filter = 'grayscale(1)';
      }
    }
  } catch (e) {}
}

function processResults() {
  document.querySelectorAll('h3').forEach(h3 => {
    const link = h3.closest('a');
    if (!link) return;
    if (link.getAttribute('data-phish-checked')) return;
    const href = link.href;
    if (!href || href.includes('google.com') || href.includes('javascript')) return;
    link.setAttribute('data-phish-checked', 'true');
    checkAndBadge(link, href);
  });
}

processResults();
const observer = new MutationObserver(() => processResults());
observer.observe(document.body, { childList: true, subtree: true });
