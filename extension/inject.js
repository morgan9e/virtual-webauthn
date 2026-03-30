(function () {
    "use strict";

    const origGet = navigator.credentials.get.bind(navigator.credentials);
    const origCreate = navigator.credentials.create.bind(navigator.credentials);

    function toB64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function fromB64url(str) {
        const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
    }

    // --- UI (toast + credential selector only, no password) ---

    const POPUP_STYLE = {
        position: "fixed", top: "20px", right: "20px",
        background: "#fff", color: "#000", border: "1px solid #bbb",
        borderRadius: "8px", padding: "16px", zIndex: "2147483647",
        maxWidth: "320px", boxShadow: "0 4px 16px rgba(0,0,0,.18)",
        fontFamily: "system-ui, -apple-system, sans-serif",
        fontSize: "14px", lineHeight: "1.4",
    };

    function showToast(message) {
        const toast = document.createElement("div");
        Object.assign(toast.style, { ...POPUP_STYLE, padding: "12px 16px", cursor: "default" });
        toast.innerHTML =
            `<div style="display:flex;align-items:center;gap:8px">` +
            `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2">` +
            `<path d="M12 2a4 4 0 0 0-4 4v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4z"/>` +
            `<circle cx="12" cy="15" r="2"/></svg>` +
            `<span>${message}</span></div>`;
        document.body.appendChild(toast);
        return toast;
    }

    function showCredentialSelector(credentials) {
        return new Promise((resolve) => {
            const popup = document.createElement("div");
            Object.assign(popup.style, POPUP_STYLE);

            const title = document.createElement("div");
            title.textContent = "Select a passkey";
            Object.assign(title.style, { margin: "0 0 12px", fontSize: "15px", fontWeight: "600" });
            popup.appendChild(title);

            const optStyle = { padding: "10px 12px", cursor: "pointer", borderRadius: "6px", transition: "background .1s" };

            credentials.forEach((cred) => {
                const opt = document.createElement("div");
                Object.assign(opt.style, optStyle);
                const date = new Date(cred.created * 1000).toLocaleString();
                opt.innerHTML =
                    `<strong>${cred.user_name || "Unknown"}</strong>` +
                    `<div style="font-size:.8em;color:#666;margin-top:2px">${date}</div>`;
                opt.onmouseover = () => (opt.style.background = "#f0f0f0");
                opt.onmouseout = () => (opt.style.background = "transparent");
                opt.onclick = () => { popup.remove(); resolve(cred); };
                popup.appendChild(opt);
            });

            const cancel = document.createElement("div");
            Object.assign(cancel.style, {
                ...optStyle, textAlign: "center", color: "#888",
                marginTop: "4px", borderTop: "1px solid #eee", paddingTop: "10px",
            });
            cancel.textContent = "Cancel";
            cancel.onmouseover = () => (cancel.style.background = "#f0f0f0");
            cancel.onmouseout = () => (cancel.style.background = "transparent");
            cancel.onclick = () => { popup.remove(); resolve(null); };
            popup.appendChild(cancel);

            document.body.appendChild(popup);
        });
    }

    // --- Messaging (no password in postMessage) ---

    const pending = new Map();
    let seq = 0;

    window.addEventListener("message", (e) => {
        if (e.source !== window || e.data?.type !== "VWEBAUTHN_RESPONSE") return;
        const resolve = pending.get(e.data.id);
        if (resolve) {
            pending.delete(e.data.id);
            resolve(e.data);
        }
    });

    function request(action, payload) {
        return new Promise((resolve, reject) => {
            const id = ++seq;
            const timer = setTimeout(() => {
                pending.delete(id);
                reject(new Error("Timed out"));
            }, 120_000);

            pending.set(id, (resp) => {
                clearTimeout(timer);
                resp.success ? resolve(resp.data) : reject(new Error(resp.error));
            });

            window.postMessage({ type: "VWEBAUTHN_REQUEST", id, action, payload }, "*");
        });
    }

    // --- Response builders ---

    function buildCreateResponse(resp) {
        return {
            id: resp.id,
            type: resp.type,
            rawId: fromB64url(resp.rawId),
            authenticatorAttachment: resp.authenticatorAttachment,
            response: {
                attestationObject: fromB64url(resp.response.attestationObject),
                clientDataJSON: fromB64url(resp.response.clientDataJSON),
                getAuthenticatorData: () => fromB64url(resp.response.authenticatorData),
                getPublicKey: () => fromB64url(resp.response.publicKey),
                getPublicKeyAlgorithm: () => Number(resp.response.pubKeyAlgo),
                getTransports: () => resp.response.transports,
            },
            getClientExtensionResults: () => ({}),
        };
    }

    function buildGetResponse(resp) {
        const cred = {
            id: resp.id,
            type: resp.type,
            rawId: fromB64url(resp.rawId),
            authenticatorAttachment: resp.authenticatorAttachment,
            response: {
                authenticatorData: fromB64url(resp.response.authenticatorData),
                clientDataJSON: fromB64url(resp.response.clientDataJSON),
                signature: fromB64url(resp.response.signature),
            },
            getClientExtensionResults: () => ({}),
        };
        if (resp.response.userHandle) {
            cred.response.userHandle = fromB64url(resp.response.userHandle);
        }
        return cred;
    }

    // --- WebAuthn overrides ---

    navigator.credentials.create = async function (options) {
        const toast = showToast("Creating passkey...");
        try {
            const pk = options.publicKey;
            const resp = await request("create", {
                publicKey: {
                    ...pk,
                    challenge: toB64url(pk.challenge),
                    user: { ...pk.user, id: toB64url(pk.user.id) },
                    excludeCredentials: pk.excludeCredentials?.map((c) => ({ ...c, id: toB64url(c.id) })),
                },
                origin: location.origin,
            });
            return buildCreateResponse(resp);
        } catch (err) {
            console.warn("[VirtualWebAuthn] create fallback:", err.message);
            return origCreate(options);
        } finally {
            toast.remove();
        }
    };

    navigator.credentials.get = async function (options) {
        const pk = options.publicKey;

        // Check if we have credentials for this rpId (no auth needed)
        try {
            const creds = await request("list", { rpId: pk.rpId || "" });
            if (Array.isArray(creds) && creds.length === 0) {
                return origGet(options);
            }
        } catch {
            return origGet(options);
        }

        const toast = showToast("Authenticating...");
        try {
            let resp = await request("get", {
                publicKey: {
                    ...pk,
                    challenge: toB64url(pk.challenge),
                    allowCredentials: pk.allowCredentials?.map((c) => ({ ...c, id: toB64url(c.id) })),
                },
                origin: location.origin,
            });

            toast.remove();

            if (Array.isArray(resp)) {
                resp = await showCredentialSelector(resp);
                if (!resp) throw new Error("User cancelled");
            }

            return buildGetResponse(resp);
        } catch (err) {
            console.warn("[VirtualWebAuthn] get fallback:", err.message);
            return origGet(options);
        } finally {
            toast.remove();
        }
    };

    console.log("[VirtualWebAuthn] Active");
})();
