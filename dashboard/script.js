document.addEventListener('DOMContentLoaded', () => {
    // Navigation Logic
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view-container');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.getAttribute('data-view');

            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            views.forEach(v => {
                if (v.id === `${viewId}-view`) v.classList.remove('hidden');
                else v.classList.add('hidden');
            });
        });
    });

    // Charts Initialization
    const ctxTrend = document.getElementById('threatTrendChart').getContext('2d');
    const ctxPie = document.getElementById('classificationPieChart').getContext('2d');
    const ctxBar = document.getElementById('attackVectorChart').getContext('2d');

    const gradient = ctxTrend.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(6, 182, 212, 0.3)');
    gradient.addColorStop(1, 'rgba(6, 182, 212, 0)');

    const threatTrendChart = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Threats Detected',
                data: [45, 52, 38, 65, 48, 22, 30],
                borderColor: '#06b6d4',
                borderWidth: 3,
                fill: true,
                backgroundColor: gradient,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: '#06b6d4'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } },
                x: { grid: { display: false }, ticks: { color: '#8b949e' } }
            }
        }
    });

    const classificationPieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Malicious', 'Suspicious'],
            datasets: [{
                data: [82, 8, 10],
                backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', usePointStyle: true } } },
            cutout: '70%'
        }
    });

    const attackVectorChart = new Chart(ctxBar, {
        type: 'bar',
        data: {
            labels: ['URL', 'Email', 'QR', 'File'],
            datasets: [{
                label: 'Attacks',
                data: [320, 180, 95, 40],
                backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b'],
                borderRadius: 8
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } },
                x: { grid: { display: false }, ticks: { color: '#8b949e' } }
            }
        }
    });

    // Incident Feed Simulation
    const incidentFeed = document.getElementById('incident-feed');
    const incidents = [
        { type: 'URL', target: 'login-secure-bank.com', score: 98, time: '2 mins ago', icon: 'fa-link', color: 'red' },
        { type: 'Email', target: 'Urgent: Password Reset', score: 85, time: '15 mins ago', icon: 'fa-envelope', color: 'orange' },
        { type: 'QR', target: 'Payment/Reward QR', score: 92, time: '1 hour ago', icon: 'fa-qrcode', color: 'red' },
        { type: 'URL', target: 'verify-account.net', score: 78, time: '3 hours ago', icon: 'fa-link', color: 'orange' }
    ];

    function renderIncidents() {
        incidentFeed.innerHTML = incidents.map(inc => `
            <div class="incident-item">
                <div class="incident-type" style="background: rgba(${inc.color === 'red' ? '239, 68, 68' : '245, 158, 11'}, 0.2); color: var(--accent-${inc.color === 'red' ? 'red' : 'yellow'})">
                    <i class="fas ${inc.icon}"></i>
                </div>
                <div class="incident-details">
                    <h5>${inc.target}</h5>
                    <p>${inc.type} Scam detected • ${inc.time}</p>
                </div>
                <div class="incident-score" style="color: var(--accent-${inc.color === 'red' ? 'red' : 'yellow'})">
                    ${inc.score}
                </div>
            </div>
        `).join('');
    }
    renderIncidents();

    // Logs Simulation
    const logsTbody = document.getElementById('logs-tbody');
    for (let i = 0; i < 10; i++) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>2026-03-01 08:${30 + i}:12</td>
            <td><span class="badge" style="color: #3b82f6">URL</span></td>
            <td>https://bit.ly/auth-${Math.floor(Math.random() * 1000)}</td>
            <td><b style="color: #ef4444">${80 + Math.floor(Math.random() * 20)}</b></td>
            <td>Malicious</td>
            <td><button style="background:none; border:none; color:#8b949e; cursor:pointer"><i class="fas fa-eye"></i></button></td>
        `;
        logsTbody.appendChild(row);
    }

    // Demo Mode Logic
    const demoCheckbox = document.getElementById('demo-mode-checkbox');
    const showcaseOverlay = document.getElementById('showcase-overlay');
    const closeShowcase = document.getElementById('close-showcase');
    const runDemoBtn = document.getElementById('run-demo-btn');
    const demoOutput = document.getElementById('demo-output');
    const demoUrlInput = document.getElementById('demo-url-input');

    demoCheckbox.addEventListener('change', () => {
        if (demoCheckbox.checked) {
            showcaseOverlay.classList.remove('hidden');
            // Trigger pulses
            document.body.classList.add('demo-active');
        } else {
            showcaseOverlay.classList.add('hidden');
        }
    });

    closeShowcase.addEventListener('click', () => {
        showcaseOverlay.classList.add('hidden');
        demoCheckbox.checked = false;
    });

    runDemoBtn.addEventListener('click', async () => {
        const url = demoUrlInput.value || "http://malicious-scam-demo.com";
        demoOutput.innerHTML = '<div class="spinner"><i class="fas fa-circle-notch fa-spin"></i> Analyzing with AI...</div>';

        try {
            const response = await fetch('http://localhost:8001/api/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            const data = await response.json();
            displayDemoResult(data);
        } catch (e) {
            // Mock result if backend unavailable
            setTimeout(() => {
                displayDemoResult({
                    url: url,
                    classification: "Malicious",
                    risk_score: 94,
                    explanation: ["Domain registered < 24h ago", "Suspicious use of IP address", "Known phishing structure detected"]
                });
            }, 1500);
        }
    });

    function displayDemoResult(data) {
        const color = data.risk_score > 70 ? '#ef4444' : (data.risk_score > 40 ? '#f59e0b' : '#10b981');
        demoOutput.innerHTML = `
            <div class="result-card">
                <div class="res-header">
                    <div class="res-score" style="color: ${color}">${data.risk_score}</div>
                    <div class="res-type" style="background: ${color}22; color: ${color}">${data.classification.toUpperCase()}</div>
                </div>
                <p style="margin-bottom: 15px; font-weight: 600;">Analysis for: <span style="color: #3b82f6">${data.url}</span></p>
                <ul class="res-reasons">
                    ${data.explanation.map(r => `<li><i class="fas fa-caret-right"></i> ${r}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Admin Blacklist Logic
    const addBlacklistBtn = document.getElementById('add-blacklist-btn');
    if (addBlacklistBtn) {
        addBlacklistBtn.addEventListener('click', async () => {
            const domain = document.getElementById('blacklist-domain').value;
            const reason = document.getElementById('blacklist-reason').value;
            const msg = document.getElementById('admin-msg');

            if (!domain) return;

            try {
                const res = await fetch('http://localhost:8001/api/admin/blacklist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain, reason })
                });
                if (res.ok) {
                    msg.innerText = "✓ Domain successfully added to global blacklist.";
                    msg.classList.remove('hidden');
                    document.getElementById('blacklist-domain').value = '';
                    setTimeout(() => msg.classList.add('hidden'), 3000);
                }
            } catch (err) {
                msg.innerText = "⚠ Simulated: Domain added to blacklist.";
                msg.classList.remove('hidden');
                msg.style.color = '#f59e0b';
                setTimeout(() => msg.classList.add('hidden'), 3000);
            }
        });
    }

    // Live Feed Simulation Logic
    const liveTerminal = document.getElementById('live-terminal');
    const scamTypes = ['Phishing URL', 'Malware Drop', 'Fake Login', 'Credential Harvester'];

    setInterval(() => {
        if (document.querySelector('.nav-item[data-view="live-feed"]').classList.contains('active')) {
            const time = new Date().toLocaleTimeString();
            const ip = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
            const isMalicious = Math.random() > 0.7;

            const p = document.createElement('p');
            if (isMalicious) {
                p.innerHTML = `<span style="color: #ef4444">[${time}] ALERT</span>: Blocked connection from ${ip} - Cause: <b style="color: #ef4444">${scamTypes[Math.floor(Math.random() * scamTypes.length)]}</b> detected.`;
            } else {
                p.innerHTML = `<span style="color: #10b981">[${time}] INFO</span>: Scanned connection from ${ip} - Status: CLEAN.`;
            }

            liveTerminal.appendChild(p);
            liveTerminal.scrollTop = liveTerminal.scrollHeight;

            // Keep feed clean
            if (liveTerminal.children.length > 50) {
                liveTerminal.removeChild(liveTerminal.children[1]); // keep the initial waiting message
            }
        }
    }, 2500);

    // Real-time stat counter simulation
    setInterval(() => {
        if (demoCheckbox.checked) {
            const el = document.getElementById('total-scanned');
            let val = parseInt(el.innerText.replace(',', ''));
            el.innerText = (val + Math.floor(Math.random() * 5)).toLocaleString();
        }
    }, 3000);
});
