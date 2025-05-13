import json
import base64
import os
import time
import hashlib
import struct
import cbor2
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from typing import Dict, Any, Optional


import getpass
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions
from fido2.utils import websafe_encode, websafe_decode


class YkFidoDevice:
    def __init__(self):
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise Exception("No FIDO2 devices found.")
        self.device = devices[0]
        print(f"Using FIDO2 device: {self.device}")

    class InputDataError(Exception):
        def __init__(self, message="", error_code=None):
            self.message = f"Input data insufficient or malformed: {message}"
            self.error_code = error_code
            super().__init__(self.message)

    def get_client(self, origin):
        class MyUserInteraction(UserInteraction):
            def prompt_up(self):
                print("\nPlease touch your security key...\n")
            def request_pin(self, permissions, rp_id):
                print(f"PIN requested for {rp_id}")
                return getpass.getpass("Enter your security key's PIN: ")

        client = Fido2Client(self.device, origin, user_interaction=MyUserInteraction())
        return client

    def create(self, create_options, origin = ""):
        print("WEBAUTHN_START_REGISTER")
        options = {"publicKey": create_options}

        if not origin:
            origin = f'https://{options["publicKey"]["rp"]["id"]}'
            if not origin:
                raise self.InputDataError("origin")
                        
        client = self.get_client(origin)

        options["publicKey"]["challenge"] = websafe_decode(options["publicKey"]["challenge"])
        options["publicKey"]["user"]["id"] = websafe_decode(options["publicKey"]["user"]["id"])

        if "excludeCredentials" in options["publicKey"]:
            for cred in options["publicKey"]["excludeCredentials"]:
                cred["id"] = websafe_decode(cred["id"])

        pk_create_options = options["publicKey"]
        challenge = pk_create_options["challenge"]
        rp = pk_create_options["rp"]
        user = pk_create_options["user"]
        pub_key_cred_params = pk_create_options["pubKeyCredParams"]

        pk_options = PublicKeyCredentialCreationOptions(rp, user, challenge, pub_key_cred_params)

        print(f"WEBAUTHN_MAKE_CREDENTIAL(RP={rp})")

        attestation = client.make_credential(pk_options)

        client_data_b64 = attestation.client_data.b64
        attestation_object = attestation.attestation_object
        credential = attestation.attestation_object.auth_data.credential_data
        if not credential:
            raise Exception()

        result = {
            "id": websafe_encode(credential.credential_id),
            "rawId": websafe_encode(credential.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": websafe_encode(attestation_object),
                "clientDataJSON": client_data_b64
            }
        }
        print(f"WEBAUTHN_ATTESTATION(ID={result['id']})")
        return result

    def get(self, get_options, origin = ""):
        print("WEBAUTHN_START_AUTHENTICATION")
        options = {"publicKey": get_options}

        if not origin:
            origin = f'https://{options["publicKey"]["rpId"]}'
            if not origin:
                raise self.InputDataError("origin")
                        
        client = self.get_client(origin)

        options["publicKey"]["challenge"] = websafe_decode(options["publicKey"]["challenge"])

        rp_id = options["publicKey"].get("rpId", "webauthn.io")
        challenge = options["publicKey"]["challenge"]

        if "allowCredentials" in options["publicKey"]:
            for cred in options["publicKey"]["allowCredentials"]:
                cred["id"] = websafe_decode(cred["id"])

        allowed = [PublicKeyCredentialDescriptor(cred["type"], cred["id"])
                        for cred in options["publicKey"]["allowCredentials"]]

        pk_options = PublicKeyCredentialRequestOptions(challenge, rp_id=rp_id, allow_credentials=allowed)

        print(f"WEBAUTHN_GET_ASSERTION(RPID={rp_id})")

        assertion_response = client.get_assertion(pk_options)

        assertion = assertion_response.get_response(0)
        if not assertion.credential_id:
            raise Exception()

        result = {
            "id": websafe_encode(assertion.credential_id),
            "rawId": websafe_encode(assertion.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": websafe_encode(assertion.authenticator_data),
                "clientDataJSON": assertion.client_data.b64,
                "signature": websafe_encode(assertion.signature),
                "userHandle": websafe_encode(assertion.user_handle) if assertion.user_handle else None
            }
        }
        print(f"WEBAUTHN_AUTHENTICATION(ID={result['id']})")
        return result


class VirtualFidoDevice:
    def __init__(self, file: str = "fido.json"):
        self.file = file
        self.credentials = {}
        self._load_credentials()

    class InputDataError(Exception):
        def __init__(self, message="", error_code=None):
            super().__init__(f"Input data insufficient or malformed: {message}")

    class CredNotFoundError(Exception):
        def __init__(self, message="No available credential found", error_code=None):
            super().__init__(message)

    def _load_credentials(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, 'r') as f:
                    self.credentials = json.load(f)
            except FileNotFoundError:
                self.credentials = {}    
    
    def _save_credentials(self):
        with open(self.file, 'w') as f:
            json.dump(self.credentials, f, indent=4)
    
    def _create_authenticator_data(self, rp_id: bytes, counter: int = 0, 
                                  user_present: bool = True, 
                                  user_verified: bool = True,
                                  credential_data: Optional[bytes] = None) -> bytes:

        rp_id_hash = hashlib.sha256(rp_id).digest()
        
        flags = 0
        if user_present:
            flags |= 1 << 0
        if user_verified:
            flags |= 1 << 2
        if credential_data is not None:
            flags |= 1 << 6
        
        counter_bytes = struct.pack(">I", counter)
        
        auth_data = rp_id_hash + bytes([flags]) + counter_bytes
        
        if credential_data is not None:
            auth_data += credential_data
            
        return auth_data

    def _get_public_key_cose(self, key) -> bytes:
        x = key.pointQ.x.to_bytes(32, byteorder='big')
        y = key.pointQ.y.to_bytes(32, byteorder='big')
        cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        return cbor2.dumps(cose_key)
    
    def _b64url(self, d):
        if isinstance(d, bytes):
            return base64.urlsafe_b64encode(d).decode('utf-8').rstrip('=')
        elif isinstance(d, str):
            return base64.urlsafe_b64decode(d + "===")


    def create(self, data: Dict[str, Any], origin: str = "") -> Dict[str, Any]:
        challenge = data.get("challenge")
        if isinstance(challenge, str):
            challenge = self._b64url(challenge)
        
        rp = data.get("rp", {})
        user = data.get("user", {})

        pub_key_params = data.get("pubKeyCredParams", [])

        alg = -7
        for param in pub_key_params:
            if param.get('type') == 'public-key' and param.get('alg') == -7:
                alg = -7
                break

        if not origin:
            origin = data.get("origin")
            if not origin:
                raise self.InputDataError("origin")
            
        rp_id = rp.get("id", "").encode()
        
        user_id = user.get("id")
        if isinstance(user_id, str):
            user_id = self._b64url(user_id)

        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')  # noqa: F841
        
        credential_id = os.urandom(16)
        credential_id_b64 = self._b64url(credential_id)
        
        cose_pubkey = self._get_public_key_cose(key)
        
        cred_id_length = struct.pack(">H", len(credential_id))
        
        aaguid = b'\x00' * 16
        attested_data = aaguid + cred_id_length + credential_id + cose_pubkey
        
        auth_data = self._create_authenticator_data(rp_id, counter=0, credential_data=attested_data)

        client_data = ('{"type":"%s","challenge":"%s","origin":"%s","crossOrigin":false}' 
                        % ("webauthn.create", self._b64url(challenge), origin)).encode()
        client_data_hash = hashlib.sha256(client_data).digest()

        signature_data = auth_data + client_data_hash
        
        h = SHA256.new(signature_data)
        signer = DSS.new(key, 'fips-186-3', encoding='der')
        signature = signer.sign(h)
        
        # Self Attestation
        attn_fmt  = "packed"
        attn_stmt = {
            "alg": -7,
            "sig": signature
        }

        attn_obj = {
            "fmt": attn_fmt,
            "attStmt": attn_stmt,
            "authData": auth_data
        }
        attn_cbor = cbor2.dumps(attn_obj)

        
        self.credentials[credential_id_b64] = {
            "private_key": private_key,
            "rp_id": rp_id.decode(),
            "user_id": self._b64url(user_id),
            "user_name": user.get('displayName', ''),
            "created": int(time.time()),
            "counter": 0
        }
        self._save_credentials()

        response = {
            "authenticatorAttachment": "cross-platform",
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "response": {
                "attestationObject": self._b64url(attn_cbor),
                "clientDataJSON": self._b64url(client_data),
                "publicKey": self._b64url(cose_pubkey),
                "authenticatorData": self._b64url(auth_data),
                "pubKeyAlgo": str(alg),
                "transports": ["usb"]
            },
            "type": "public-key"
        }
        return response


    def get(self, data: Dict[str, Any], origin: str = "") -> Dict[str, Any]:
        challenge = data.get("challenge")
        if isinstance(challenge, str):
            challenge = self._b64url(challenge)
        
        rp_id = data.get("rpId", "").encode('utf-8')
        if not rp_id:
            raise self.InputDataError("rp_id")

        if not origin:
            origin = data.get("origin")
            if not origin:
                raise self.InputDataError("origin")

        allowed_credential = data.get("allowCredentials")
        cred = None
        if allowed_credential:
            for credential in allowed_credential:
                credential_id_b64 = credential["id"]
                if self.credentials.get(credential_id_b64):
                    cred = self.credentials[credential_id_b64]
                    break
        else:
            for credential_id_b64, my_credential in self.credentials.items():
                if my_credential["rp_id"] == rp_id.decode():
                    cred = my_credential
                    break
        if not cred:
            raise self.CredNotFoundError()
        
        counter = cred.get("counter", 0) + 1
        cred["counter"] = counter
        
        auth_data = self._create_authenticator_data(
            rp_id=rp_id, 
            counter=counter,
            user_present=True,
            user_verified=True
        )
    
        client_data = ('{"type":"%s","challenge":"%s","origin":"%s","crossOrigin":false}' 
                        % ("webauthn.get", self._b64url(challenge), origin)).encode()
        client_data_hash = hashlib.sha256(client_data).digest()

        signature_data = auth_data + client_data_hash
        
        key = ECC.import_key(cred["private_key"])
        h = SHA256.new(signature_data)
        signer = DSS.new(key, 'fips-186-3', encoding='der')
        signature = signer.sign(h)
        
        self._save_credentials()
        
        response = {
            "authenticatorAttachment": "cross-platform",
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "response": {
                "authenticatorData": self._b64url(auth_data),
                "clientDataJSON": self._b64url(client_data),
                "signature": self._b64url(signature),
                "userHandle": cred["user_id"]
            },
            "type": "public-key"
        }
        return response


if __name__=="__main__":
    import requests

    sess = requests.Session()
    fido = VirtualFidoDevice()

    payload = {
        "algorithms": ["es256"], "attachment": "all", "attestation": "none", "discoverable_credential": "preferred",
        "hints": [], "user_verification": "preferred", "username": "asdf"
    }
    resp = sess.post("https://webauthn.io/registration/options", json=payload)
    print(resp.json())
    data = fido.create(resp.json(), origin="https://webauthn.io")
    data["rawId"] = data["id"]
    print(data)
    resp = sess.post("https://webauthn.io/registration/verification", json={"response": data, "username": "asdf"})
    print(resp.json())
    print()

    sess.get("https://webauthn.io/logout")

    payload = {"username":"asdf", "user_verification":"preferred", "hints":[]}
    resp = sess.post("https://webauthn.io/authentication/options", json=payload, headers={"origin": "https://webauthn.io"})
    print(resp.json())
    data = fido.get(resp.json(), origin="https://webauthn.io")
    print(data)
    data["rawId"] = data["id"]
    resp = sess.post("https://webauthn.io/authentication/verification", json={"response": data, "username": "asdf"})
    print(resp.json())