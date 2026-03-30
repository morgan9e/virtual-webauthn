const s = document.createElement("script");
s.src = chrome.runtime.getURL("inject.js");
s.onload = () => s.remove();
(document.documentElement || document.head).appendChild(s);

window.addEventListener("message", async (event) => {
    if (event.source !== window || event.data?.type !== "VWEBAUTHN_REQUEST") return;

    const { id, action, payload } = event.data;
    try {
        const response = await chrome.runtime.sendMessage({
            type: "VWEBAUTHN_REQUEST", action, payload,
        });
        window.postMessage({ type: "VWEBAUTHN_RESPONSE", id, ...response }, "*");
    } catch (error) {
        window.postMessage({ type: "VWEBAUTHN_RESPONSE", id, success: false, error: error.message }, "*");
    }
});
