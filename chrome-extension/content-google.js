// Runs on Google Search results pages
// Adds risk badges next to each result and hides HIGH risk ones

const API = 'http://localhost:8080';

function getBadgeHTML(level, score) {
  const colors = {
    LOW:    { bg: '#14532d', color: '#4ade80' },
    MEDIUM: { bg: '#713f12', color: '#fbbf24' },
    HIGH:   { bg: '#7f1d1d', color: '#f87171' },
  };
  const c = colors[level] || colors.LOW;
  return `<span style="
    display:inline-block;
    margin-left:8px;
    padding:2px 8px;
    border-radius:12px;
    font-size:11px;
    font-weight:700;
    background:${c.bg};
    color:${c.color};
    vertical-align:middle;
    font-family:sans-serif;
  ">${level} (${score}/100)</span>`;
}

async function checkAndBadge(linkEl, url) {
  try {
    const res = await fetch(`${API}/check?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    const level = data.riskLevel
      ? (data.riskLevel.includes('HIGH') ? 'HIGH' : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW')
      : 'LOW';

    // Add badge next to the link
    const badge = document.createElement('span');
    badge.innerHTML = getBadgeHTML(level, data.riskScore);
    linkEl.parentElement.appendChild(badge);

    // Hide HIGH risk results
    if (level === 'HIGH') {
      const resultBlock = linkEl.closest('[data-sokoban-container], .g, [jscontroller]');
      if (resultBlock) {
        resultBlock.style.opacity = '0.3';
        resultBlock.style.filter = 'grayscale(1)';
        const warn = document.createElement('div');
        warn.textContent = '⚠️ Phishing Detector flagged this result as HIGH RISK';
        warn.style.cssText = 'color:#f87171;font-size:12px;font-weight:600;margin-top:4px;font-family:sans-serif;';
        resultBlock.prepend(warn);
      }
    }
  } catch (e) {
    // Silently fail if backend is unreachable
  }
}

function processResults() {
  // Google search result links
  const links = document.querySelectorAll('a[href^="http"]:not([data-phish-checked])');
  links.forEach(link => {
    const href = link.href;
    if (!href || href.includes('google.com')) return;
    link.setAttribute('data-phish-checked', 'true');
    checkAndBadge(link, href);
  });
}

// Run on load
processResults();

// Also watch for dynamically loaded results
const observer = new MutationObserver(() => processResults());
observer.observe(document.body, { childList: true, subtree: true });
