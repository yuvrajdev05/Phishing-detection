const processedLinks = new Set();
const scanResults = new Map();

async function scanPageLinks() {
    const links = Array.from(document.querySelectorAll('a[href^="http"]'));
    const newLinks = links.filter(link => !processedLinks.has(link.href));

    for (const link of newLinks) {
        processedLinks.add(link.href);
        const url = link.href;

        try {
            // For demo, we throttle and send to backend
            const response = await fetch('http://localhost:8001/api/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            const data = await response.json();

            if (data.risk_score > 70) {
                link.classList.add('phish-shield-link-high');
                link.title = `PhishShield AI Warning: High Risk (${data.risk_score}/100). Reason: ${data.explanation[0]}`;
            }
        } catch (e) {
            // Backend offline, skip injection
        }
    }
}

function injectEmailBadge() {
    // Gmail specific: find subject line or sender info
    // This is a simplified selector for demo purposes
    const subjectHeaders = document.querySelectorAll('h2.hP');
    subjectHeaders.forEach(header => {
        if (!header.querySelector('.phish-shield-badge')) {
            const badge = document.createElement('span');
            badge.className = 'phish-shield-badge badge-danger';
            badge.innerText = 'AI Scanned: Secure'; // Defaulting to secure for badge
            // header.appendChild(badge); // Disabled for now to prevent UI clutter without real analysis
        }
    });
}

// Watch for DOM changes (for SPAs like Gmail)
const observer = new MutationObserver(() => {
    scanPageLinks();
    injectEmailBadge();
});

observer.observe(document.body, { childList: true, subtree: true });

// Initial scan
scanPageLinks();
console.log("PhishShield AI Content Script Active");
