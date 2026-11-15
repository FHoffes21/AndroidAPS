"""Recover an existing AAPS signing key to an authenticated, private archive."""
import base64
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AAPS-RECOVERY-1\x00"
FILES = ("keystore.jks", "keyStoreInfo.txt")


class RecoveryError(Exception):
    """A fixed diagnostic message safe for public logs."""


def key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


def encrypt(payload, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(key(password, salt)).encrypt(nonce, payload, header)


def decrypt(archive, password):
    if not archive.startswith(MAGIC) or len(archive) < len(MAGIC) + 44:
        raise RecoveryError("Invalid archive format")
    start = len(MAGIC)
    salt, nonce = archive[start:start + 16], archive[start + 16:start + 28]
    header = archive[:start + 28]
    return AESGCM(key(password, salt)).decrypt(nonce, archive[len(header):], header)


def zip_payload(store, info):
    data = io.BytesIO()
    with ZipFile(data, "w", ZIP_DEFLATED) as archive:
        archive.writestr(FILES[0], store)
        archive.writestr(FILES[1], info)
    return data.getvalue()


def parse_bundle(encoded, size):
    fields = base64.b64decode("".join(encoded.split()), validate=True).decode("utf-8").split("|")
    if len(fields) != size or any(not field or "\n" in field or "\r" in field for field in fields):
        raise RecoveryError("Invalid secret bundle format")
    return fields


def original_key():
    combined = os.getenv("KEYSTORE_SET")
    if combined:
        data, storepass, alias, keypass = parse_bundle(combined, 4)
    else:
        data, storepass, alias, keypass = (
            os.environ[name] for name in ("KEYSTORE_BASE64", "KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD")
        )
    if not all((data, storepass, alias, keypass)):
        raise RecoveryError("Signing secret is incomplete")
    return base64.b64decode("".join(data.split()), validate=True), storepass, alias, keypass


def validate_key(keystore, storepass, alias, keypass):
    with TemporaryDirectory(prefix="aaps-keystore-") as directory:
        store = Path(directory) / "keystore.jks"
        cert = Path(directory) / "certificate.der"
        store.write_bytes(keystore)
        env = {"PATH": os.environ["PATH"], "AAPS_STORE_PASS": storepass, "AAPS_KEY_PASS": keypass}
        common = ["-alias", alias, "-keystore", str(store), "-storepass:env", "AAPS_STORE_PASS"]
        for args in (
            ["-certreq", "-keypass:env", "AAPS_KEY_PASS", "-file", str(Path(directory) / "proof.csr")],
            ["-exportcert", "-file", str(cert)],
        ):
            result = subprocess.run(["keytool", *args, *common], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                raise RecoveryError("The stored key, alias or passwords did not validate")
        return hashlib.sha256(cert.read_bytes()).hexdigest()


def json_request(url, data=None, headers=None):
    with urlopen(Request(url, data=data, headers=headers or {}), timeout=45) as response:
        return json.load(response)


def upload_private_drive(archive, name):
    print("Checking Google Drive authorization.", flush=True)
    client_id, refresh_token = parse_bundle(os.environ["GDRIVE_OAUTH2"], 2)
    auth = json_request("https://oauth2.googleapis.com/token", urlencode({
        "client_id": client_id, "refresh_token": refresh_token, "grant_type": "refresh_token",
    }).encode())
    print("Drive authorization accepted; uploading ciphertext.", flush=True)
    boundary = os.urandom(24).hex().encode()
    body = (
        b"--" + boundary + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
        + json.dumps({"name": name, "parents": ["root"]}).encode()
        + b"\r\n--" + boundary + b"\r\nContent-Type: application/octet-stream\r\n\r\n"
        + archive + b"\r\n--" + boundary + b"--\r\n"
    )
    fields = urlencode({"uploadType": "multipart", "fields": "id"})
    result = json_request("https://www.googleapis.com/upload/drive/v3/files?" + fields, body, {
        "Authorization": "Bearer " + auth["access_token"],
        "Content-Type": "multipart/related; boundary=" + boundary.decode(),
    })
    fields = urlencode({"fields": "name,shared,permissions(type,role)"})
    result = json_request(f"https://www.googleapis.com/drive/v3/files/{result['id']}?{fields}", headers={
        "Authorization": "Bearer " + auth["access_token"],
    })
    if result.get("name") != name or result.get("shared") is not False or [
        (p.get("type"), p.get("role")) for p in result.get("permissions", [])
    ] != [("user", "owner")]:
        raise RecoveryError("Drive did not confirm owner-only access to the encrypted file")


def export():
    password = os.environ["AAPS_RECOVERY_PASSWORD"]
    if len(password) < 24:
        raise RecoveryError("Recovery password must contain at least 24 characters")
    print("Recovery password length accepted; reading signing configuration.", flush=True)
    store, storepass, alias, keypass = original_key()
    print("Signing configuration decoded; validating the original key.", flush=True)
    fingerprint = validate_key(store, storepass, alias, keypass)
    print("Original signing key validated.", flush=True)
    info = f"ALIAS={alias}\nKEYSTORE_PASSWORD={storepass}\nKEY_PASSWORD={keypass}\nCERT_SHA256={fingerprint}\n"
    archive = encrypt(zip_payload(store, info), password)
    name = f"aaps-keystore-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}.aapsenc"
    upload_private_drive(archive, name)
    print(f"Existing signing key validated. Signing certificate SHA-256: {fingerprint}")
    print(f"Encrypted archive uploaded to owner-only Google Drive root: {name}")


def unpack(source, destination):
    password = getpass.getpass("Recovery password: ")
    payload = decrypt(source.read_bytes(), password)
    with ZipFile(io.BytesIO(payload)) as archive:
        if sorted(archive.namelist()) != sorted(FILES):
            raise RecoveryError("Unexpected archive contents")
        destination.mkdir(mode=0o700)
        for name in FILES:
            with (destination / name).open("xb") as target:
                target.write(archive.read(name))
    print("Keystore and recovery information saved.")


def self_test():
    password = "synthetic example password for CI"
    payload = zip_payload(b"synthetic keystore bytes", "synthetic information")
    archive = encrypt(payload, password)
    assert decrypt(archive, password) == payload
    assert encrypt(payload, password) != archive
    for invalid, key_password in ((archive, password + "x"), (archive[:-1] + bytes([archive[-1] ^ 1]), password)):
        try:
            decrypt(invalid, key_password)
        except InvalidTag:
            continue
        raise AssertionError("Authentication check failed")
    print("Authenticated round trip, fresh randomness, wrong-password and tampering tests passed.")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        if sys.argv[1:] == ["test"]:
            self_test()
        elif sys.argv[1:] == ["export"]:
            export()
        elif len(sys.argv) == 4 and sys.argv[1] == "decrypt":
            unpack(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            raise RecoveryError("Invalid command")
    except Exception as error:
        # Never print remote responses, credentials or exceptions that may include them.
        print(f"Keystore recovery failed ({type(error).__name__}).", file=sys.stderr)
        if isinstance(error, RecoveryError):
            print(error, file=sys.stderr)
        if isinstance(error, InvalidTag):
            print("The password is incorrect or the archive was modified.", file=sys.stderr)
        raise SystemExit(1) from None
