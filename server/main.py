import argparse
import logging
import traceback
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from passkey import VirtualPasskey, PhysicalPasskey, _AuthError, _b64url_decode

log = logging.getLogger("vwebauthn")

app = FastAPI(title="Virtual WebAuthn")
passkey_cls = VirtualPasskey

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


class WebAuthnRequest(BaseModel):
    type: str
    data: Dict[str, Any]


@app.post("/")
async def handle(req: WebAuthnRequest):
    webauthn = passkey_cls()
    options = req.data.get("publicKey", {})
    origin = req.data.get("origin", "")
    log.info("POST / type=%s origin=%s", req.type, origin)
    rp = options.get("rp", {}).get("id") or options.get("rpId", "")
    if rp:
        log.info("  rp_id=%s", rp)

    try:
        if req.type == "create":
            user = options.get("user", {})
            log.info("  create user=%s", user.get("displayName") or user.get("name", "?"))
            result = webauthn.create(options, origin)
            log.info("  created credential id=%s", result.get("id", "?")[:16] + "...")
            return result
        elif req.type == "get":
            allowed = options.get("allowCredentials", [])
            log.info("  get allowCredentials=%d", len(allowed))
            result = webauthn.get(options, origin)
            log.info("  authenticated credential id=%s counter=%s",
                     result.get("id", "?")[:16] + "...",
                     result.get("response", {}).get("authenticatorData", "?"))
            return result
        else:
            raise HTTPException(status_code=400, detail=f"Unknown type: {req.type}")
    except HTTPException:
        raise
    except _AuthError as e:
        log.warning("  auth error: %s", e)
        raise HTTPException(status_code=401, detail=str(e))
    except (VirtualPasskey.CredNotFoundError, VirtualPasskey.InputDataError,
            PhysicalPasskey.InputDataError) as e:
        log.warning("  client error: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error("  unhandled error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ping")
def ping():
    mode = "physical" if passkey_cls is PhysicalPasskey else "virtual"
    log.debug("GET /ping mode=%s", mode)
    return {"status": "ok", "mode": mode}


@app.get("/credentials")
def list_credentials():
    log.info("GET /credentials")
    if passkey_cls is PhysicalPasskey:
        raise HTTPException(status_code=400, detail="Not available in physical mode")
    webauthn = VirtualPasskey()
    try:
        password = webauthn._ask_password("Virtual WebAuthn — List Credentials")
        creds = webauthn._load_credentials(password)
    except _AuthError as e:
        log.warning("  auth error: %s", e)
        raise HTTPException(status_code=401, detail=str(e))
    log.info("  loaded %d credentials", len(creds))
    return [
        {
            "id": cid,
            "rp_id": _b64url_decode(c["rp_id"]).decode("utf-8", errors="ignore"),
            "user_name": c.get("user_name", ""),
            "created": c.get("created", 0),
            "counter": c.get("counter", 0),
        }
        for cid, c in creds.items()
    ]


@app.delete("/credentials/{credential_id}")
def delete_credential(credential_id: str):
    log.info("DELETE /credentials/%s", credential_id[:16] + "...")
    if passkey_cls is PhysicalPasskey:
        raise HTTPException(status_code=400, detail="Not available in physical mode")
    webauthn = VirtualPasskey()
    try:
        password = webauthn._ask_password("Virtual WebAuthn — Delete Credential")
        webauthn.credentials = webauthn._load_credentials(password)
    except _AuthError as e:
        log.warning("  auth error: %s", e)
        raise HTTPException(status_code=401, detail=str(e))
    if credential_id not in webauthn.credentials:
        log.warning("  credential not found")
        raise HTTPException(status_code=404, detail="Credential not found")
    del webauthn.credentials[credential_id]
    webauthn._save_credentials(password)
    log.info("  deleted successfully")
    return {"status": "deleted"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Virtual WebAuthn Server")
    parser.add_argument(
        "--mode", choices=["virtual", "physical"], default="virtual",
        help="Passkey mode: virtual (software keys) or physical (USB FIDO2 device)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20492)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.mode == "physical":
        passkey_cls = PhysicalPasskey
    else:
        passkey_cls = VirtualPasskey

    log.info("Mode: %s", args.mode)
    uvicorn.run(app, host=args.host, port=args.port, log_level="debug" if args.verbose else "info")
