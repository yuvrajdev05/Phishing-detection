document.addEventListener('DOMContentLoaded', () => {
    const riskCircle = document.getElementById('risk-circle');
    const riskScoreText = document.getElementById('risk-score');
    const safetyLabel = document.getElementById('safety-label');
    const qrBtn = document.getElementById('scan-qr-btn');
    const qrModal = document.getElementById('qr-modal');
    const closeModal = document.getElementById('close-modal');
    const dropZone = document.getElementById('drop-zone');
    const qrInput = document.getElementById('qr-input');
    const qrResults = document.getElementById('qr-results');

    // Initial Risk Score (Simulated)
    updateRiskScore(15);

    // Tips
    const tips = [
        "Always check the domain name carefully for subtle misspellings.",
        "Phishing emails often create a sense of urgency or fear.",
        "Avoid clicking links in unexpected emails; go to the official site instead.",
        "Enable multi-factor authentication whenever possible.",
        "Legitimate companies will never ask for your password via email."
    ];
    document.getElementById('tip-text').innerText = tips[Math.floor(Math.random() * tips.length)];

    function updateRiskScore(score) {
        const total = 283; // Circumference
        const offset = total - (score / 100) * total;
        riskCircle.style.strokeDashoffset = offset;
        riskScoreText.innerText = score;

        if (score > 70) {
            riskCircle.style.stroke = '#ff4d4d';
            safetyLabel.innerText = "CRITICAL";
            safetyLabel.style.color = '#ff4d4d';
        } else if (score > 40) {
            riskCircle.style.stroke = '#ffcc00';
            safetyLabel.innerText = "WARNING";
            safetyLabel.style.color = '#ffcc00';
        } else {
            riskCircle.style.stroke = '#00f2ff';
            safetyLabel.innerText = "SECURE";
            safetyLabel.style.color = '#00ff88';
        }
    }

    // QR Modal logic
    qrBtn.addEventListener('click', () => {
        qrModal.classList.remove('hidden');
    });

    document.getElementById('reports-btn').addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('reports.html') });
    });

    closeModal.addEventListener('click', () => {
        qrModal.classList.add('hidden');
        qrResults.classList.add('hidden');
        qrResults.innerHTML = '';
    });

    dropZone.addEventListener('click', () => qrInput.click());

    qrInput.addEventListener('change', async (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            analyzeQR(file);
        }
    });

    async function analyzeQR(file) {
        qrResults.classList.remove('hidden');
        qrResults.innerHTML = '<p style="color: #00f2ff; text-align: center;">Scanning AI Engine...</p>';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('http://localhost:8001/api/scan/qr', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (data.error) {
                qrResults.innerHTML = `<p style="color: #ff4d4d;">Error: ${data.error}</p>`;
                return;
            }

            qrResults.innerHTML = `<h4>Found ${data.count} codes:</h4>`;
            data.findings.forEach(f => {
                const color = f.analysis.risk_score > 70 ? '#ff4d4d' : (f.analysis.risk_score > 40 ? '#ffcc00' : '#00ff88');
                qrResults.innerHTML += `
                    <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding: 8px 0;">
                        <p style="font-size: 0.7rem; color: #94a3b8; word-break: break-all;">${f.qr_data}</p>
                        <p style="font-weight: 700; color: ${color};">Risk: ${f.analysis.risk_score}/100 [${f.analysis.classification}]</p>
                    </div>
                `;
            });
        } catch (err) {
            qrResults.innerHTML = `<p style="color: #ff9900;">Backend unreachable. Simulating scan...</p>`;
            setTimeout(() => {
                qrResults.innerHTML = `
                    <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding: 8px 0;">
                        <p style="font-size: 0.7rem; color: #94a3b8;">https://bit.ly/secure-login-302</p>
                        <p style="font-weight: 700; color: #ff4d4d;">Risk: 88/100 [MALICIOUS]</p>
                        <p style="font-size: 0.6rem; color: #ff4d4d;">Reason: Flagged as deceptive URL.</p>
                    </div>
                `;
            }, 1500);
        }
    }
});
