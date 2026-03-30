const HOST_NAME = "com.example.virtual_webauthn";

let port = null;
let seq = 0;
const pending = new Map();
let sessionKey = null;

function connect() {
    if (port) return;
    try {
        port = chrome.runtime.connectNative(HOST_NAME);
    } catch {
        return;
    }

    port.onMessage.addListener((msg) => {
        if (msg.sessionKey) {
            sessionKey = msg.sessionKey;
        }
        const cb = pending.get(msg.id);
        if (cb) {
            pending.delete(msg.id);
            cb(msg);
        }
    });

    port.onDisconnect.addListener(() => {
        port = null;
        for (const [id, cb] of pending) {
            cb({ id, success: false, error: "Host disconnected" });
        }
        pending.clear();
        updateIcon(false);
    });

    updateIcon(true);
}

function sendNative(msg) {
    return new Promise((resolve, reject) => {
        connect();
        if (!port) {
            reject(new Error("Cannot connect to native host"));
            return;
        }
        const id = ++seq;
        const timer = setTimeout(() => {
            pending.delete(id);
            reject(new Error("Timed out"));
        }, 120_000);

        pending.set(id, (resp) => {
            clearTimeout(timer);
            resolve(resp);
        });

        port.postMessage({ ...msg, id });
    });
}

// --- Icon status ---

let lastStatus = null;

function updateIcon(connected) {
    const status = connected ? "ok" : "err";
    if (status === lastStatus) return;
    lastStatus = status;
    const icon = connected ? "icon-green.svg" : "icon-red.svg";
    const title = connected
        ? "Virtual WebAuthn — Connected"
        : "Virtual WebAuthn — Disconnected";
    chrome.action.setIcon({ path: icon });
    chrome.action.setTitle({ title });
}

async function pingLoop() {
    try {
        const resp = await sendNative({ type: "ping" });
        updateIcon(resp.success === true);
    } catch {
        updateIcon(false);
    }
    setTimeout(pingLoop, 10_000);
}

pingLoop();

// --- Message relay from content script ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== "VWEBAUTHN_REQUEST") return;

    const msg = {
        type: message.action,
        data: message.payload,
    };

    // Password from content.js (already in isolated context)
    if (message.password) {
        msg.password = message.password;
    } else if (sessionKey) {
        msg.sessionKey = sessionKey;
    }

    if (message.action === "list" && message.rpId) {
        msg.rpId = message.rpId;
    }

    sendNative(msg)
        .then((resp) => {
            if (!resp.success) {
                const err = resp.error || "";
                if (err.includes("session") || err.includes("Session")) {
                    sessionKey = null;
                }
            }
            sendResponse(resp);
        })
        .catch((error) => {
            sendResponse({ success: false, error: error.message });
        });
    return true;
});
