const API = 'https://phishing-url-detector-je19.onrender.com';

Office.onReady(() => {
    // Office is ready
});

async function scanEmail() {
    const btn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('result');

    btn.disabled = true;
    btn.textContent = 'Scanning...';
    resultDiv.innerHTML = '<div class="loading">Analyzing email...</div>';

    try {
        const item = Office.context.mailbox.item;

        // Get email body
        item.body.getAsync(Office.CoercionType.Text, async (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) {
                resultDiv.innerHTML = '<div class="error-msg">Could not read email body.</div>';
                btn.disabled = false;
                btn.textContent = 'Scan This Email';
                return;
            }

            const body = result.value;

            try {
                const res = await fetch(`${API}/check-email`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: body
                });
                if (!res.ok) {
                    const msg = res.status === 429
                        ? 'Too many requests right now — please wait a minute and try again.'
                        : 'Could not complete scan. Please try again.';
                    resultDiv.innerHTML = '<div class="error-msg">' + msg + '</div>';
                    btn.disabled = false;
                    btn.textContent = 'Scan This Email';
                    return;
                }
                const data = await res.json();
                renderResult(data, resultDiv);
            } catch (e) {
                resultDiv.innerHTML = '<div class="error-msg">Could not reach backend.</div>';
            }

            btn.disabled = false;
            btn.textContent = 'Scan This Email';
        });

    } catch (e) {
        resultDiv.innerHTML = '<div class="error-msg">Error: ' + e.message + '</div>';
        btn.disabled = false;
        btn.textContent = 'Scan This Email';
    }
}

function renderResult(data, el) {
    if (data.error) {
        el.innerHTML = '<div class="error-msg">' + data.error + '</div>';
        return;
    }

    const level = !data.riskLevel ? 'LOW'
        : data.riskLevel.includes('HIGH') ? 'HIGH'
        : data.riskLevel.includes('MEDIUM') ? 'MEDIUM' : 'LOW';

    const barColor = level === 'HIGH' ? '#f87171' : level === 'MEDIUM' ? '#fbbf24' : '#4ade80';
    const warnings = data.warnings || [];
    const cleanAi = data.aiAnalysis
        ? data.aiAnalysis.replace(/\*\*(.*?)\*\*/g, '$1').replace(/\*(.*?)\*/g, '$1')
        : null;

    let html = '<span class="risk-badge risk-' + level + '">' + (data.riskLevel || 'LOW') + '</span>';

    html += '<div class="score-wrap"><div class="score-label"><span>Risk Score</span><span>' + data.riskScore + '/100</span></div>';
    html += '<div class="score-bar"><div class="score-fill" style="width:' + data.riskScore + '%;background:' + barColor + '"></div></div></div>';

    if (warnings.length === 0) {
        html += '<div class="no-warnings">No threats detected</div>';
    } else {
        html += '<div class="warnings-title">Warnings</div><ul class="warnings-list">';
        warnings.forEach(w => { html += '<li>' + w + '</li>'; });
        html += '</ul>';
    }

    if (cleanAi) {
        html += '<div class="ai-block"><div class="ai-label">AI Analysis</div>';
        html += '<div class="ai-text">' + cleanAi + '</div></div>';
    }

    el.innerHTML = html;
}
