# Virtual WebAuthn

### Unsafe implementation of WebAuthn for private key transparency.

### `fido.py`

Virtual WebAuthn implemention of `navigator.credentials.get()` and `navigator.credentials.create()`, with self-attestation.

### `webauthn_server.py`

Simple FastAPI server that acts as proxy for `fido.py` and browser environment.

Use `webauthn_server.js` in userscript.js (like TamperMonkey), WebAuthn requests will be forwarded to your local script.



Private key for your Passkeys are stored in JSON file, you can backup your private key since **YOU OWN THE KEY**.

Works on most WebAuthn websites, including Google, Microsoft.