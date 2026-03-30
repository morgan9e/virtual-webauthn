const API_URL = "http://127.0.0.1:20492";

async function apiFetch(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
    }
    const response = await fetch(API_URL + path, opts);
    if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Server error: ${response.status}`);
    }
    return response.json();
}

// --- Icon status polling ---

let lastStatus = null;

async function updateIcon() {
    try {
        await apiFetch("GET", "/ping");
        if (lastStatus !== "ok") {
            chrome.action.setIcon({ path: "icon-green.svg" });
            chrome.action.setTitle({ title: "Virtual WebAuthn — Connected" });
            lastStatus = "ok";
        }
    } catch {
        if (lastStatus !== "err") {
            chrome.action.setIcon({ path: "icon-red.svg" });
            chrome.action.setTitle({ title: "Virtual WebAuthn — Disconnected" });
            lastStatus = "err";
        }
    }
}

updateIcon();
setInterval(updateIcon, 5000);

// --- Message relay ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "VWEBAUTHN_REQUEST") {
        apiFetch("POST", "", { type: message.action, data: message.payload })
            .then((data) => sendResponse({ success: true, data }))
            .catch((error) => sendResponse({ success: false, error: error.message }));
        return true;
    }
});
