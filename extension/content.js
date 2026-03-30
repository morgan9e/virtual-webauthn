const s = document.createElement("script");
s.src = chrome.runtime.getURL("inject.js");
s.onload = () => s.remove();
(document.documentElement || document.head).appendChild(s);

// --- Password prompt (closed shadow DOM, isolated context) ---

function showPasswordPrompt(title, needsConfirm) {
    return new Promise((resolve) => {
        const host = document.createElement("div");
        host.style.cssText = "position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647";
        const shadow = host.attachShadow({ mode: "closed" });

        shadow.innerHTML = `
        <style>
            .overlay { position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.3); }
            .popup {
                position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
                background:#fff;color:#000;border:1px solid #bbb;border-radius:8px;padding:16px;
                max-width:320px;box-shadow:0 4px 16px rgba(0,0,0,.18);
                font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.4;
            }
            .title { margin:0 0 12px;font-size:15px;font-weight:600; }
            input {
                width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;
                font-size:14px;margin-bottom:8px;box-sizing:border-box;
            }
            .err { color:#dc2626;font-size:12px;margin-bottom:8px;display:none; }
            .btns { display:flex;gap:8px;justify-content:flex-end; }
            button {
                padding:8px 16px;border:none;border-radius:4px;font-size:13px;cursor:pointer;font-weight:500;
            }
            .cancel { background:#f0f0f0;color:#333; }
            .ok { background:#222;color:#fff; }
        </style>
        <div class="overlay"></div>
        <div class="popup">
            <div class="title"></div>
            <input type="password" class="pw" placeholder="Password">
            ${needsConfirm ? '<input type="password" class="pw2" placeholder="Confirm password">' : ""}
            <div class="err"></div>
            <div class="btns">
                <button class="cancel">Cancel</button>
                <button class="ok">Unlock</button>
            </div>
        </div>`;

        const cleanup = () => host.remove();

        shadow.querySelector(".title").textContent = title;
        const pw = shadow.querySelector(".pw");
        const pw2 = shadow.querySelector(".pw2");
        const errEl = shadow.querySelector(".err");

        const submit = () => {
            if (!pw.value) {
                errEl.textContent = "Password required";
                errEl.style.display = "";
                return;
            }
            if (needsConfirm && pw.value !== pw2.value) {
                errEl.textContent = "Passwords do not match";
                errEl.style.display = "";
                return;
            }
            const val = pw.value;
            cleanup();
            resolve(val);
        };

        shadow.querySelector(".ok").onclick = submit;
        shadow.querySelector(".cancel").onclick = () => { cleanup(); resolve(null); };
        shadow.querySelector(".overlay").onclick = () => { cleanup(); resolve(null); };

        const onKey = (e) => { if (e.key === "Enter") submit(); };
        pw.addEventListener("keydown", onKey);
        if (pw2) pw2.addEventListener("keydown", onKey);

        document.body.appendChild(host);
        pw.focus();
    });
}

// --- Message relay with auth handling ---

async function sendToHost(msg) {
    const response = await chrome.runtime.sendMessage(msg);
    if (chrome.runtime.lastError) throw new Error(chrome.runtime.lastError.message);
    return response;
}

async function handleRequest(action, payload, rpId) {
    const msg = { type: "VWEBAUTHN_REQUEST", action, payload };
    if (rpId) msg.rpId = rpId;

    // No-auth actions pass through directly
    if (action === "list" || action === "status" || action === "ping") {
        return sendToHost(msg);
    }

    // Try with session first (no password)
    let response = await sendToHost(msg);

    // If session worked, done
    if (response.success) return response;

    // Need password — check if first-time setup
    const isSessionError = response.error?.includes("session") || response.error?.includes("Session")
        || response.error?.includes("Password or session");
    if (!isSessionError) return response; // real error, don't retry

    let statusResp;
    try {
        statusResp = await sendToHost({ type: "VWEBAUTHN_REQUEST", action: "status", payload: {} });
    } catch {
        return response;
    }
    const needsSetup = statusResp.success && statusResp.data?.needsSetup;

    const title = needsSetup
        ? "Virtual WebAuthn — Set Password"
        : `Virtual WebAuthn — ${action === "create" ? "Create Credential" : "Authenticate"}`;

    // Retry loop — allow 3 password attempts
    for (let attempt = 0; attempt < 3; attempt++) {
        const password = await showPasswordPrompt(
            attempt > 0 ? "Wrong password — try again" : title,
            needsSetup,
        );
        if (!password) return { success: false, error: "Password prompt cancelled" };

        msg.password = password;
        const retry = await sendToHost(msg);
        if (retry.success || !retry.error?.includes("password")) return retry;
    }

    return { success: false, error: "Too many failed attempts" };
}

window.addEventListener("message", async (event) => {
    if (event.source !== window || event.data?.type !== "VWEBAUTHN_REQUEST") return;

    const { id, action, payload } = event.data;
    try {
        const response = await handleRequest(action, payload, event.data.rpId);
        window.postMessage({ type: "VWEBAUTHN_RESPONSE", id, ...response }, "*");
    } catch (error) {
        window.postMessage({ type: "VWEBAUTHN_RESPONSE", id, success: false, error: error.message }, "*");
    }
});
