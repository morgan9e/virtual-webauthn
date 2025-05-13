from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any
import uvicorn
import json
from fido import VirtualFidoDevice as FidoDevice

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class WebAuthnRequest(BaseModel):
    type: str
    data: Dict[str, Any]

@app.post('/')
async def handle(param: WebAuthnRequest):
    if param.type == "get":
        try:
            options = param.data.get("publicKey", {})
            print(f"webauthn.get {json.dumps(options, indent=4)}")
            webauthn = FidoDevice()
            assertion = webauthn.get(options, param.data.get("origin", ""))
            return assertion

        except Exception as e:
            import traceback
            print(f"error.webauthn.get: {e}")
            print(traceback.format_exc())
            raise HTTPException(status_code=500, detail=str(e))
    
    elif param.type == "create":
        try:
            options = param.data.get("publicKey", {})
            print(f"webauthn.create {json.dumps(options, indent=4)}")
            webauthn = FidoDevice()
            attestation = webauthn.create(options, param.data.get("origin", ""))
            return attestation

        except Exception as e:
            import traceback
            print(f"error.webauthn.create: {e}")
            print(traceback.format_exc())
            raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=20492)
