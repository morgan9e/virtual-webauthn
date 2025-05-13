# Virtual WebAuthn

### Locally stored WebAuthn Passkey

### `passkey.py`

Virtual WebAuthn implemention of `navigator.credentials.get()` and `navigator.credentials.create()`, with self-attestation.

### `webauthn_server.py`

Simple FastAPI server that acts as proxy for `passkey.py` on browser environment.

Use `webauthn_server.js` in userscript.js (like TamperMonkey), WebAuthn requests will be forwarded to your local script.


Private key for your Passkeys are stored in JSON file, you can backup your private key.

Works on most WebAuthn websites, including Google, Microsoft.