const API_URL = 'http://localhost:8001/api/scan/url';
const scanCache = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only handle main frame navigation
    if (details.frameId !== 0) return;

    const url = details.url;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

    console.log(`Analyzing: ${url}`);

    // Check cache
    if (scanCache.has(url)) {
        handleScanResult(details.tabId, scanCache.get(url));
        return;
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        const result = await response.json();
        scanCache.set(url, result);
        handleScanResult(details.tabId, result);
    } catch (err) {
        console.error("Backend unreachable, skipping real-time AI scan.");
    }
});

function handleScanResult(tabId, result) {
    if (result.classification === 'Malicious' && result.risk_score > 70) {
        const blockUrl = chrome.runtime.getURL('block.html') + `?url=${encodeURIComponent(result.url)}&score=${result.risk_score}&reason=${encodeURIComponent(result.explanation[0])}`;
        chrome.tabs.update(tabId, { url: blockUrl });
    } else if (result.classification === 'Suspicious' || result.risk_score > 40) {
        // Show a notification or inject a warning popup
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: 'PhishShield Warning',
            message: `Caution: This site (${new URL(result.url).hostname}) looks suspicious. Risk Score: ${result.risk_score}`,
            priority: 2
        });
    }
}

// Global stats tracking
chrome.storage.local.get(['threatsBlocked', 'urlsScanned'], (data) => {
    if (!data.threatsBlocked) chrome.storage.local.set({ threatsBlocked: 0 });
    if (!data.urlsScanned) chrome.storage.local.set({ urlsScanned: 0 });
});
