const API = 'https://phishing-url-detector-je19.onrender.com';

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// URL Check
document.getElementById('checkUrl').addEventListener('click', async () => {
  const url = document.getElementById('urlInput').value.trim();
  const resultDiv = document.getElementById('urlResult');
  if (!url) return;

  resultDiv.className = 'result';
  resultDiv.innerHTML = '<div class="loading">Analyzing...</div>';

  try {
    const res = await fetch(`${API}/check?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    renderUrlResult(data, resultDiv);
  } catch (e) {
    resultDiv.innerHTML = '<div class="error-msg">Could not reach backend. Is the server running?</div>';
  }
});

// Email Check
document.getElementById('checkEmail').addEventListener('click', async () => {
  const body = document.getElementById('emailInput').value.trim();
  const resultDiv = document.getElementById('emailResult');
  if (!body) return;

  resultDiv.className = 'result';
  resultDiv.innerHTML = '<div class="loading">Analyzing...</div>';

  try {
    const res = await fetch(`${API}/check-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: body
    });
    const data = await res.json();
    renderEmailResult(data, resultDiv);
  } catch (e) {
    resultDiv.innerHTML = '<div class="error-msg">Could not reach backend. Is the server running?</div>';
  }
});

// Enter key support
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('checkUrl').click();
});

function riskLevel(level) {
  if (!level) return 'LOW';
  if (level.includes('HIGH')) return 'HIGH';
  if (level.includes('MEDIUM')) return 'MEDIUM';
  return 'LOW';
}

function renderUrlResult(data, el) {
  if (data.error) {
    el.innerHTML = `<div class="error-msg">${data.error}</div>`;
    return;
  }
  const level = riskLevel(data.riskLevel);
  const warnings = data.warnings || [];
  el.innerHTML = `
    <span class="risk-badge risk-${level}">${data.riskLevel || 'LOW'}</span>
    <div class="score">Risk Score: ${data.riskScore}/100</div>
    <div class="meta">
      ${data.protocol ? '<b>Protocol:</b> ' + data.protocol + ' &nbsp;' : ''}
      ${data.domain ? '<b>Domain:</b> ' + data.domain : ''}
    </div>
    ${warnings.length === 0
      ? '<div class="no-warnings">✅ No threats detected</div>'
      : '<ul class="warnings-list">' + warnings.map(w => `<li>${w}</li>`).join('') + '</ul>'
    }
  `;
}

function renderEmailResult(data, el) {
  if (data.error) {
    el.innerHTML = `<div class="error-msg">${data.error}</div>`;
    return;
  }
  const level = riskLevel(data.riskLevel);
  const warnings = data.warnings || [];
  const aiBlock = data.aiAnalysis
    ? `<div style="margin-top:10px;padding:10px;background:#0a0a1a;border-radius:8px;border-left:3px solid #4f46e5;">
        <div style="font-size:10px;color:#555;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">🤖 AI Analysis</div>
        <div style="font-size:12px;color:#ccc;line-height:1.5;">${data.aiAnalysis}</div>
       </div>`
    : '';
  el.innerHTML = `
    <span class="risk-badge risk-${level}">${data.riskLevel || 'LOW'}</span>
    <div class="score">Risk Score: ${data.riskScore}/100</div>
    ${warnings.length === 0
      ? '<div class="no-warnings">✅ No threats detected</div>'
      : '<ul class="warnings-list">' + warnings.map(w => `<li>${w}</li>`).join('') + '</ul>'
    }
    ${aiBlock}
  `;
}
