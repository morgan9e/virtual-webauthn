import json
import base64
import logging
import os
import time
import hashlib
import struct
import subprocess
import cbor2
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from typing import Dict, Any, Optional

log = logging.getLogger("vwebauthn.passkey")

ZENITY_BINARY = os.environ.get("ZENITY_BINARY", "zenity")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "===")

def _zenity(args: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            [ZENITY_BINARY] + args,
            capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise RuntimeError(f"{ZENITY_BINARY} is not installed")
    if result.returncode != 0:
        return None
    return result.stdout.strip()

def _zenity_password(title: str) -> str:
    pw = _zenity(["--password", "--title", title])
    if pw is None:
        raise _AuthError("Password prompt cancelled")
    if not pw:
        raise _AuthError("Empty password")
    return pw

def _zenity_entry(title: str, text: str, hide: bool = False) -> str:
    args = ["--entry", "--title", title, "--text", text]
    if hide:
        args.append("--hide-text")
    return _zenity(args)


class _AuthError(Exception):
    def __init__(self, message="Authentication failed"):
        super().__init__(message)


class PhysicalPasskey:
    class InputDataError(Exception):
        def __init__(self, message=""):
            super().__init__(f"Input data insufficient or malformed: {message}")

    AuthenticationError = _AuthError

    def __init__(self):
        from fido2.hid import CtapHidDevice
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise RuntimeError("No FIDO2 devices found")
        self.device = devices[0]

    def _get_client(self, origin):
        from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction

        device = self.device

        class ZenityInteraction(UserInteraction):
            def prompt_up(self):
                _zenity(["--notification", "--text", "Touch your security key..."], timeout=1)

            def request_pin(self, permissions, rp_id):
                pin = _zenity_entry(
                    "Physical WebAuthn",
                    f"Enter PIN for your security key\n\n{device}",
                    hide=True
                )
                if pin is None:
                    raise _AuthError("PIN prompt cancelled")
                return pin

        collector = DefaultClientDataCollector(origin)
        return Fido2Client(self.device, collector, user_interaction=ZenityInteraction())

    def create(self, create_options, origin=""):
        from fido2.utils import websafe_encode, websafe_decode

        options = create_options
        if not origin:
            origin = f'https://{options["rp"]["id"]}'
            if not origin:
                raise self.InputDataError("origin")

        client = self._get_client(origin)

        options["challenge"] = websafe_decode(options["challenge"])
        options["user"]["id"] = websafe_decode(options["user"]["id"])

        for cred in options.get("excludeCredentials", []):
            cred["id"] = websafe_decode(cred["id"])

        reg = client.make_credential(options)

        return {
            "authenticatorAttachment": "cross-platform",
            "id": reg.id,
            "rawId": reg.id,
            "type": "public-key",
            "response": {
                "attestationObject": _b64url_encode(bytes(reg.response.attestation_object)),
                "clientDataJSON": _b64url_encode(bytes(reg.response.client_data)),
            },
        }

    def get(self, get_options, origin=""):
        from fido2.utils import websafe_encode, websafe_decode

        options = get_options
        if not origin:
            origin = f'https://{options["rpId"]}'
            if not origin:
                raise self.InputDataError("origin")

        client = self._get_client(origin)

        options["challenge"] = websafe_decode(options["challenge"])

        for cred in options.get("allowCredentials", []):
            cred["id"] = websafe_decode(cred["id"])

        assertion = client.get_assertion(options).get_response(0)

        return {
            "authenticatorAttachment": "cross-platform",
            "id": assertion.id,
            "rawId": assertion.id,
            "type": "public-key",
            "response": {
                "authenticatorData": _b64url_encode(bytes(assertion.response.authenticator_data)),
                "clientDataJSON": _b64url_encode(bytes(assertion.response.client_data)),
                "signature": _b64url_encode(bytes(assertion.response.signature)),
                "userHandle": _b64url_encode(bytes(assertion.response.user_handle)) if assertion.response.user_handle else None,
            },
        }


class VirtualPasskey:
    SCRYPT_N = 2**18
    SCRYPT_R = 8
    SCRYPT_P = 1
    SCRYPT_KEYLEN = 32

    def __init__(self, file: str = "passkey.json"):
        self.file = file
        self.credentials = {}

    class InputDataError(Exception):
        def __init__(self, message=""):
            super().__init__(f"Input data insufficient or malformed: {message}")

    class CredNotFoundError(Exception):
        def __init__(self, message="No matching credential found"):
            super().__init__(message)

    AuthenticationError = _AuthError

    def _ask_password(self, title: str = "Virtual WebAuthn") -> str:
        if not os.path.exists(self.file):
            log.info("No credential file, prompting new password")
            pw = _zenity_password(f"{title} — Set Password")
            pw2 = _zenity_password(f"{title} — Confirm Password")
            if pw != pw2:
                raise self.AuthenticationError("Passwords do not match")
            self._save_credentials(pw)
            log.info("Created credential file %s", self.file)
            return pw
        log.debug("Prompting password for %s", self.file)
        return _zenity_password(title)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode(), salt=salt,
            n=self.SCRYPT_N, r=self.SCRYPT_R, p=self.SCRYPT_P, dklen=self.SCRYPT_KEYLEN,
            maxmem=128 * self.SCRYPT_N * self.SCRYPT_R * 2,
        )

    def _load_credentials(self, password: str) -> dict:
        if not os.path.exists(self.file):
            log.debug("Credential file not found, starting fresh")
            return {}
        with open(self.file, 'r') as f:
            try:
                envelope = json.load(f)
            except (json.JSONDecodeError, ValueError):
                log.warning("Credential file is corrupted, starting fresh")
                return {}
        # Unencrypted legacy format
        if "salt" not in envelope:
            log.debug("Loaded unencrypted legacy credentials")
            return envelope
        log.debug("Deriving key and decrypting credentials")
        salt = _b64url_decode(envelope["salt"])
        nonce = _b64url_decode(envelope["nonce"])
        ciphertext = _b64url_decode(envelope["ciphertext"])
        tag = _b64url_decode(envelope["tag"])
        key = self._derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            raise self.AuthenticationError("Wrong password")
        creds = json.loads(plaintext.decode())
        log.debug("Decrypted %d credentials", len(creds))
        return creds

    def _save_credentials(self, password: str):
        log.debug("Encrypting and saving %d credentials to %s", len(self.credentials), self.file)
        salt = os.urandom(32)
        nonce = os.urandom(12)
        key = self._derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = json.dumps(self.credentials, indent=4).encode()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        envelope = {
            "salt": _b64url_encode(salt),
            "nonce": _b64url_encode(nonce),
            "ciphertext": _b64url_encode(ciphertext),
            "tag": _b64url_encode(tag),
        }
        with open(self.file, 'w') as f:
            json.dump(envelope, f, indent=4)
        log.debug("Credentials saved")

    @staticmethod
    def _build_authenticator_data(
        rp_id: bytes, counter: int = 0,
        user_present: bool = True,
        user_verified: bool = True,
        credential_data: Optional[bytes] = None,
    ) -> bytes:
        rp_id_hash = hashlib.sha256(rp_id).digest()
        flags = 0
        if user_present:
            flags |= 0x01
        if user_verified:
            flags |= 0x04
        if credential_data is not None:
            flags |= 0x40
        auth_data = rp_id_hash + bytes([flags]) + struct.pack(">I", counter)
        if credential_data is not None:
            auth_data += credential_data
        return auth_data

    @staticmethod
    def _cose_public_key(key) -> bytes:
        x = key.pointQ.x.to_bytes(32, byteorder='big')
        y = key.pointQ.y.to_bytes(32, byteorder='big')
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})

    def _find_credential(self, data: Dict[str, Any]) -> tuple:
        allowed = data.get("allowCredentials") or []

        if allowed:
            for entry in allowed:
                cred_id = entry["id"]
                if cred_id in self.credentials:
                    return cred_id, self.credentials[cred_id]
            raise self.CredNotFoundError()

        rp_id = data.get("rpId", "")
        for cred_id, cred_data in self.credentials.items():
            stored_rp = _b64url_decode(cred_data["rp_id"]).decode('utf-8', errors='ignore')
            if stored_rp == rp_id:
                return cred_id, cred_data
        raise self.CredNotFoundError()

    def create(self, data: Dict[str, Any], origin: str = "") -> Dict[str, Any]:
        password = self._ask_password("Virtual WebAuthn — Create Credential")
        self.credentials = self._load_credentials(password)

        challenge = data.get("challenge")
        if isinstance(challenge, str):
            challenge = _b64url_decode(challenge)

        rp = data.get("rp", {})
        user = data.get("user", {})

        alg = -7
        for param in data.get("pubKeyCredParams", []):
            if param.get("type") == "public-key" and param.get("alg") == -7:
                break

        if not origin:
            origin = data.get("origin")
            if not origin:
                raise self.InputDataError("origin")

        rp_id = rp.get("id", "").encode()

        user_id = user.get("id")
        if isinstance(user_id, str):
            user_id = _b64url_decode(user_id)

        key = ECC.generate(curve='P-256')
        credential_id = os.urandom(16)
        credential_id_b64 = _b64url_encode(credential_id)
        cose_pubkey = self._cose_public_key(key)

        attested_data = (
            b'\x00' * 16
            + struct.pack(">H", len(credential_id))
            + credential_id
            + cose_pubkey
        )
        auth_data = self._build_authenticator_data(rp_id, counter=0, credential_data=attested_data)

        attestation_cbor = cbor2.dumps({
            "fmt": "none",
            "authData": auth_data,
            "attStmt": {}
        })

        client_data_json = json.dumps({
            "challenge": _b64url_encode(challenge),
            "origin": origin,
            "type": "webauthn.create",
            "crossOrigin": False,
        }).encode()

        self.credentials[credential_id_b64] = {
            "private_key": key.export_key(format='PEM'),
            "rp_id": _b64url_encode(rp_id),
            "user_id": _b64url_encode(user_id),
            "user_name": user.get('displayName', ''),
            "created": int(time.time()),
            "counter": 0,
        }
        self._save_credentials(password)

        return {
            "authenticatorAttachment": "cross-platform",
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "attestationObject": _b64url_encode(attestation_cbor),
                "clientDataJSON": _b64url_encode(client_data_json),
                "authenticatorData": _b64url_encode(auth_data),
                "publicKey": _b64url_encode(cose_pubkey),
                "pubKeyAlgo": str(alg),
                "transports": ["internal"],
            },
        }

    def get(self, data: Dict[str, Any], origin: str = "") -> Dict[str, Any]:
        password = self._ask_password("Virtual WebAuthn — Authenticate")
        self.credentials = self._load_credentials(password)

        challenge = data.get("challenge")
        if isinstance(challenge, str):
            challenge = _b64url_decode(challenge)

        credential_id_b64, cred = self._find_credential(data)

        rp_id = data.get("rpId", "").encode('utf-8')
        if not rp_id:
            raise self.InputDataError("rpId")

        if not origin:
            origin = data.get("origin")
            if not origin:
                raise self.InputDataError("origin")

        counter = cred.get("counter", 0) + 1
        cred["counter"] = counter

        auth_data = self._build_authenticator_data(rp_id, counter=counter)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": _b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": False,
        }, separators=(',', ':')).encode()
        client_data_hash = hashlib.sha256(client_data).digest()

        key = ECC.import_key(cred["private_key"])
        h = SHA256.new(auth_data + client_data_hash)
        signature = DSS.new(key, 'fips-186-3', encoding='der').sign(h)

        self._save_credentials(password)

        return {
            "authenticatorAttachment": "cross-platform",
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "authenticatorData": _b64url_encode(auth_data),
                "clientDataJSON": _b64url_encode(client_data),
                "signature": _b64url_encode(signature),
            },
        }


Passkey = VirtualPasskey


if __name__ == "__main__":
    import requests

    sess = requests.Session()
    passkey = Passkey()

    reg_payload = {
        "algorithms": ["es256"], "attachment": "all", "attestation": "none",
        "discoverable_credential": "preferred", "hints": [],
        "user_verification": "preferred", "username": "test",
    }
    options = sess.post("https://webauthn.io/registration/options", json=reg_payload).json()
    cred = passkey.create(options, origin="https://webauthn.io")
    cred["rawId"] = cred["id"]
    result = sess.post("https://webauthn.io/registration/verification",
                       json={"response": cred, "username": "test"}).json()
    print("Registration:", result)

    sess.get("https://webauthn.io/logout")

    auth_payload = {"username": "test", "user_verification": "preferred", "hints": []}
    options = sess.post("https://webauthn.io/authentication/options", json=auth_payload).json()
    assertion = passkey.get(options, origin="https://webauthn.io")
    assertion["rawId"] = assertion["id"]
    result = sess.post("https://webauthn.io/authentication/verification",
                       json={"response": assertion, "username": "test"}).json()
    print("Authentication:", result)
