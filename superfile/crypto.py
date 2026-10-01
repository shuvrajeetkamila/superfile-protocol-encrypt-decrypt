"""
SUPERFILE — container encryption (AES-256-GCM).

Threat model & design
---------------------
A .sfp container stores object data in several chunks.  The *payload* chunks
carry user data (or data derived from it) and therefore MUST be encrypted
together — encrypting only the original bytes would leave the full decoded
text sitting in CONT in plain JSON:

    META  object identity: id, filename, format, size, checksum, adapter, ...
    CONT  obj.content as JSON  ← decoded text/markdown/JSON/CSV lives here
    HIST  transformation history
    RTBL  relationships (may carry child names)
    OTBL  child-object summaries (names/format/size)
    OFMT  original-format table (filename, checksum, detection notes)
    OBYT  the original raw file bytes
    BLOB  decoded binary blobs referenced from CONT (e.g. pixel frames)
    KIDS  nested child containers (each of which has its own CONT/OBYT/BLOB)

all of them are encrypted.  Only framing stays in the clear, exactly as
required:

    MAGIC + header (version/flags)          framing
    chunk table: tag + length per chunk     framing
    ENCR                                    not secret: it says HOW to decrypt
    CKSM                                    checksum of the ENCRYPTED bytes

What the ENCR chunk holds (plaintext JSON):

    {"v":1, "mode":"password"|"device", "kdf":"pbkdf2-sha256"|"hkdf-sha256",
     "kdf_params":{"iterations":N} | {"hash":"sha256","info":"..."},
     "salt":b64, "nonce":b64, "device_ref":uuid (device mode),
     "chunks":["META", ...]}

Cryptography
------------
* AES-256-GCM (`cryptography`), one fresh random 96-bit *base* nonce per file.
* Every encrypted chunk gets its own nonce: ``base XOR counter`` (distinct
  counters -> distinct nonces, so a per-chunk nonce is never reused).
* Each chunk is authenticated with AAD = b"SUPERFILE/v1" + tag + chunk index,
  so chunks cannot be swapped, reordered, or moved between files.
* Password mode: PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte random salt.
* Device mode (Windows only): a per-install master key in the user data dir,
  protected with DPAPI (CryptProtectData, via ctypes — no extra dependency);
  the per-file key is HKDF-SHA256(master, salt).
* The container KNOWN-answer is its CKSM, recomputed over the encrypted body,
  so a damaged or truncated file is rejected before any decryption.

Nothing here ever writes a plaintext container to disk, and no plaintext
buffer is left in the returned bytes: the output is assembled from ciphertext
only.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import secrets
import struct
import sys
import uuid

from .protocol import (CHUNK_BLOB, CHUNK_CKSM, CHUNK_CONT, CHUNK_ENCR, CHUNK_HIST,
                       CHUNK_KIDS, CHUNK_META, CHUNK_OBYT, CHUNK_OFMT, CHUNK_OTBL,
                       CHUNK_RTBL, ENCRYPTED_CONTAINER_MESSAGE, HEADER_SIZE, MAGIC)

try:  # the only third-party dependency of this module
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - surfaced as a clear error at runtime
    HAVE_CRYPTOGRAPHY = False
    InvalidTag = Exception

# every payload chunk (i.e. everything except the framing, ENCR and CKSM)
PAYLOAD_TAGS = (CHUNK_META, CHUNK_CONT, CHUNK_HIST, CHUNK_RTBL, CHUNK_OTBL,
                CHUNK_OFMT, CHUNK_OBYT, CHUNK_BLOB, CHUNK_KIDS)

try:  # optional strength upgrade — never required to read or write a file
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_raw
    HAVE_ARGON2 = True
except Exception:
    HAVE_ARGON2 = False

PBKDF2_ITERATIONS = 600_000
KDF_PBKDF2 = "pbkdf2-sha256"          # default: pure stdlib, always available
KDF_ARGON2ID = "argon2id"             # optional: memory-hard, needs argon2-cffi
# Argon2id cost: 64 MiB, 3 passes, 4 lanes (OWASP-recommended ballpark shape)
ARGON2_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
KNOWN_KDFS = (KDF_PBKDF2, KDF_ARGON2ID)
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
_AAD_PREFIX = b"SUPERFILE/v1"
GCM_TAG_BYTES = 16

MODE_PASSWORD = "password"
MODE_DEVICE = "device"


class EncryptionError(Exception):
    """Anything the user should see verbatim: wrong password, wrong device, ..."""


class DeviceLockUnavailable(EncryptionError):
    """Device (DPAPI) mode cannot work in this environment."""


# ---------------------------------------------------------------------------
# dependency check
# ---------------------------------------------------------------------------

def cryptography_version() -> str:
    try:
        import cryptography
        return getattr(cryptography, "__version__", "unknown")
    except Exception:
        return "not installed"


def _require_crypto() -> None:
    if not HAVE_CRYPTOGRAPHY:
        raise EncryptionError(
            "AES-256-GCM is unavailable: the 'cryptography' package is not "
            "installed in this interpreter")


# ---------------------------------------------------------------------------
# device key storage (Windows DPAPI via ctypes — no pywin32, no keyring pkg)
# ---------------------------------------------------------------------------

def device_lock_supported() -> bool:
    """Device mode is Windows-only in this build (DPAPI has no Linux/macOS twin)."""
    return sys.platform == "win32" and HAVE_CRYPTOGRAPHY


def device_key_path() -> str:
    """Per-user keyring file, next to the other SUPERFILE user data."""
    base = os.environ.get("SUPERFILE_DEVICE_DIR")
    if not base:
        if os.name == "nt":
            root = os.environ.get("LOCALAPPDATA") or os.path.join(
                os.path.expanduser("~"), "AppData", "Local")
        else:
            root = os.path.join(os.path.expanduser("~"), ".local", "share")
        base = os.path.join(root, "Superfile")
    return os.path.join(base, "device-key.json")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(protect: bool, data: bytes) -> bytes:
    """CryptProtectData / CryptUnprotectData with correct 64-bit ctypes setup."""
    if os.name != "nt":
        raise DeviceLockUnavailable(
            "device-lock mode is Windows-only in this build (no DPAPI on this OS)")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_wchar_p,
                   ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_ulong, ctypes.POINTER(_DataBlob)]
    fn.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    blob_in = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    ok = fn(ctypes.byref(blob_in), "SUPERFILE device key", None, None, None, 0x1,
            ctypes.byref(blob_out))
    if not ok:
        err = ctypes.get_last_error()
        raise EncryptionError(f"Windows DPAPI {'protect' if protect else 'unprotect'} "
                              f"failed (error {err})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def load_keyring() -> dict:
    path = device_key_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise EncryptionError(f"device key file {path} is unreadable: {exc}")


def save_keyring(ring: dict) -> None:
    path = device_key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ring, fh)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def get_or_create_device_key() -> tuple:
    """Return (device_ref, master_key) — creating and DPAPI-protecting it once."""
    if not device_lock_supported():
        raise DeviceLockUnavailable(
            "device-lock mode is Windows-only in this build "
            f"(this is {sys.platform or os.name}) — use a password instead")
    ring = load_keyring()
    entry = ring.get("device")
    if entry and entry.get("device_ref") and entry.get("protected"):
        master = _dpapi(False, base64.b64decode(entry["protected"]))
        return entry["device_ref"], master
    master = secrets.token_bytes(KEY_BYTES)
    device_ref = str(uuid.uuid4())
    ring["device"] = {"device_ref": device_ref,
                      "protected": base64.b64encode(_dpapi(True, master)).decode(),
                      "created": str(uuid.uuid4())[:8]}
    save_keyring(ring)
    return device_ref, master


def device_key_for(device_ref: str) -> bytes:
    """Look up the DPAPI-protected master key for this file's device reference."""
    if not device_lock_supported():
        raise DeviceLockUnavailable(
            "device-lock mode is Windows-only in this build — this file needs "
            "its password (or a Windows machine that holds the device key)")
    ring = load_keyring()
    entry = ring.get("device") or {}
    if not entry or entry.get("device_ref") != device_ref:
        raise EncryptionError(
            "This file was locked to a different device, or needs a password.")
    try:
        return _dpapi(False, base64.b64decode(entry["protected"]))
    except EncryptionError:
        raise EncryptionError(
            "This file was locked to a different device, or needs a password.")


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------

def derive_password_key(password: str, salt: bytes, kdf: str = KDF_PBKDF2) -> bytes:
    """Stretch the password into a 256-bit key with the requested KDF."""
    _require_crypto()
    if not password:
        raise EncryptionError("password mode needs a non-empty password")
    if len(salt) < SALT_BYTES:
        raise EncryptionError("the encryption salt is too short — file is damaged")
    if kdf == KDF_PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                   PBKDF2_ITERATIONS, dklen=KEY_BYTES)
    if kdf == KDF_ARGON2ID:
        if not HAVE_ARGON2:
            raise EncryptionError("argon2id needs the argon2-cffi package — not available here")
        return _argon2_raw(password.encode("utf-8"), salt, hash_len=KEY_BYTES,
                           type=_Argon2Type.ID,
                           time_cost=ARGON2_PARAMS["time_cost"],
                           memory_cost=ARGON2_PARAMS["memory_cost"],
                           parallelism=ARGON2_PARAMS["parallelism"])
    raise EncryptionError(f"unsupported key derivation {kdf!r} — file is damaged")


def derive_device_key(master: bytes, salt: bytes) -> bytes:
    _require_crypto()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt,
                info=b"SUPERFILE-device-v1").derive(master)


def _nonce_for(base: bytes, index: int) -> bytes:
    """base XOR index — distinct indexes give distinct 96-bit nonces."""
    n = int.from_bytes(base, "big") ^ (index + 1)
    return n.to_bytes(NONCE_BYTES, "big")


def _aad(tag: bytes, index: int) -> bytes:
    return _AAD_PREFIX + tag + struct.pack(">I", index)


# ---------------------------------------------------------------------------
# container framing helpers (structure only — never touches payload meaning)
# ---------------------------------------------------------------------------

def _iter(data: bytes, start: int):
    pos, n = start, len(data)
    while pos < n:
        if n - pos < 12:
            raise EncryptionError("truncated chunk header")
        tag = data[pos:pos + 4]
        (length,) = struct.unpack_from(">Q", data, pos + 4)
        payload_off = pos + 12
        end = payload_off + length
        if end > n:
            raise EncryptionError(f"chunk {tag!r} claims {length} bytes — file truncated")
        yield tag, data[payload_off:end], pos
        pos = end
        if tag == CHUNK_CKSM:
            return


def _pack(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack(">Q", len(payload)) + payload


def _split(data: bytes):
    """(header_bytes, [(tag, payload)], cksm_offset) with framing validated."""
    if len(data) < HEADER_SIZE + 12 or data[:8] != MAGIC:
        raise EncryptionError("not a SUPERFILE container")
    vmaj, vmin, hdr_size, flags, _res = struct.unpack_from(">HHII12s", data, 8)
    if hdr_size < HEADER_SIZE or hdr_size > len(data):
        raise EncryptionError("invalid header_size")
    chunks, cksm_off = [], None
    for tag, payload, off in _iter(data, hdr_size):
        if tag == CHUNK_CKSM:
            cksm_off = off
            break
        chunks.append((tag, payload))
    if cksm_off is None:
        raise EncryptionError("missing CKSM checksum chunk")
    if cksm_off + 12 + 32 != len(data):
        raise EncryptionError("trailing data after checksum")
    payload = data[cksm_off + 12:cksm_off + 12 + 32]
    if hashlib.sha256(data[:cksm_off]).hexdigest() != payload.hex():
        raise EncryptionError("checksum mismatch — container is corrupt or was modified")
    return data[:hdr_size], chunks, cksm_off


def available_kdfs() -> list:
    """Password KDFs this installation can write (pbkdf2 always, argon2id if installed)."""
    out = [KDF_PBKDF2]
    if HAVE_ARGON2:
        out.append(KDF_ARGON2ID)
    return out


def is_encrypted(data: bytes) -> bool:
    """True if the container carries an ENCR chunk (framing-level test only)."""
    if not data.startswith(MAGIC):
        return False
    try:
        hdr_size = struct.unpack_from(">I", data, 12)[0]
        for tag, _payload, _off in _iter(data, hdr_size):
            if tag == CHUNK_ENCR:
                return True
    except Exception:
        return False
    return False


def encr_header(data: bytes) -> dict:
    """The ENCR JSON block (never secret: it says how to decrypt)."""
    hdr_size = struct.unpack_from(">I", data, 12)[0]
    for tag, payload, _off in _iter(data, hdr_size):
        if tag == CHUNK_ENCR:
            return json.loads(payload.decode("utf-8"))
    raise EncryptionError("not an encrypted .sfp (no ENCR chunk)")


# ---------------------------------------------------------------------------
# encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_container(plain: bytes, mode: str, password: str | None = None,
                      kdf: str = KDF_PBKDF2) -> bytes:
    """Encrypt every payload chunk of a .sfp container.  Returns new .sfp bytes."""
    _require_crypto()
    header, chunks, _cksm = _split(plain)
    if any(tag == CHUNK_ENCR for tag, _ in chunks):
        raise EncryptionError("this .sfp is already encrypted")

    salt = secrets.token_bytes(SALT_BYTES)
    base_nonce = secrets.token_bytes(NONCE_BYTES)
    encr = {"v": 1, "nonce": base64.b64encode(base_nonce).decode(),
            "salt": base64.b64encode(salt).decode(), "chunks": []}

    if mode == MODE_PASSWORD:
        if kdf not in KNOWN_KDFS:
            raise EncryptionError(f"unknown key derivation {kdf!r}")
        key = derive_password_key(str(password or ""), salt, kdf)
        if kdf == KDF_ARGON2ID:
            encr.update(mode=MODE_PASSWORD, kdf=KDF_ARGON2ID,
                        kdf_params=dict(ARGON2_PARAMS, hash="sha256", kind="id"))
        else:
            encr.update(mode=MODE_PASSWORD, kdf=KDF_PBKDF2,
                        kdf_params={"iterations": PBKDF2_ITERATIONS, "hash": "sha256"})
    elif mode == MODE_DEVICE:
        device_ref, master = get_or_create_device_key()
        key = derive_device_key(master, salt)
        encr.update(mode=MODE_DEVICE, kdf="hkdf-sha256",
                    kdf_params={"hash": "sha256", "info": "SUPERFILE-device-v1"},
                    device_ref=device_ref)
    else:
        raise EncryptionError(f"unknown encryption mode {mode!r}")

    aes = AESGCM(key)
    body = bytearray(header)
    index = 0
    for tag, payload in chunks:
        if tag in PAYLOAD_TAGS and payload:
            # one distinct nonce per chunk; AAD binds tag + position so chunks
            # cannot be swapped, reordered or moved to another file
            ct = aes.encrypt(_nonce_for(base_nonce, index), payload, _aad(tag, index))
            body += _pack(tag, ct)
            encr["chunks"].append(tag.decode("latin-1"))
            index += 1
        else:
            body += _pack(tag, payload)      # empty payloads / unknown tags pass through
    # ENCR is written first, now that the list of encrypted chunks is known
    out = bytearray(body[:len(header)])
    out += _pack(CHUNK_ENCR, json.dumps(encr, ensure_ascii=False).encode("utf-8"))
    out += body[len(header):]
    out += _pack(CHUNK_CKSM, hashlib.sha256(bytes(out)).digest())   # checksum of the ENCRYPTED bytes
    return bytes(out)


def decrypt_container(data: bytes, mode: str, password: str | None = None) -> bytes:
    """Decrypt a .sfp container back to a plain (unencrypted) .sfp.

    Returns bytes identical to the original plaintext container: the header is
    kept, payloads are restored and CKSM is recomputed over the rebuilt body —
    for any container written by this project that equals the original value.
    """
    _require_crypto()
    header, chunks, _cksm = _split(data)
    encr = None
    for tag, payload in chunks:
        if tag == CHUNK_ENCR:
            encr = json.loads(payload.decode("utf-8"))
    if encr is None:
        raise EncryptionError("this .sfp is not encrypted (no ENCR chunk)")

    file_mode = encr.get("mode")
    salt = base64.b64decode(encr.get("salt") or "")
    base_nonce = base64.b64decode(encr.get("nonce") or "")
    if len(base_nonce) != NONCE_BYTES:
        raise EncryptionError("the ENCR nonce is malformed — file is damaged")

    if mode == MODE_DEVICE:
        if file_mode != MODE_DEVICE:
            # not a device-mode file, or the reference is unknown here
            raise EncryptionError(
                "This file was locked to a different device, or needs a password.")
        master = device_key_for(str(encr.get("device_ref") or ""))
        key = derive_device_key(master, salt)
    elif mode == MODE_PASSWORD:
        if file_mode != MODE_PASSWORD:
            raise EncryptionError(
                "This file was locked to a different device, or needs a password.")
        key = derive_password_key(str(password or ""), salt,
                                  str(encr.get("kdf") or KDF_PBKDF2))
    else:
        raise EncryptionError(f"unknown decryption mode {mode!r}")

    aes = AESGCM(key)
    out = bytearray(header)
    plain_out = bytearray()
    index = 0
    decrypted_tags = set()
    for tag, payload in chunks:
        if tag == CHUNK_ENCR:
            continue
        if tag in PAYLOAD_TAGS and payload:
            try:
                pt = aes.decrypt(_nonce_for(base_nonce, index), payload, _aad(tag, index))
            except InvalidTag:
                if file_mode == MODE_PASSWORD:
                    raise EncryptionError(
                        "wrong password — AES-256-GCM could not authenticate this "
                        "file (or the file is damaged)")
                raise EncryptionError(
                    "the device key does not match this file (or the file is damaged)")
            out += _pack(tag, pt)
            decrypted_tags.add(tag.decode("latin-1"))
            index += 1
        else:
            out += _pack(tag, payload)
    out += _pack(CHUNK_CKSM, hashlib.sha256(bytes(out)).digest())
    plain = bytes(out)

    listed = set(encr.get("chunks") or [])
    if listed and listed != decrypted_tags:
        raise EncryptionError(
            f"the ENCR chunk lists {sorted(listed)} but {sorted(decrypted_tags)} "
            f"were present — the file was tampered with")
    return plain


# ---------------------------------------------------------------------------
# small helpers used by the API and the UI
# ---------------------------------------------------------------------------

def describe(data: bytes) -> dict:
    """Public, non-secret description of an encrypted container (for the UI)."""
    try:
        info = encr_header(data)
    except Exception as exc:
        return {"encrypted": False, "error": str(exc)}
    return {
        "encrypted": True,
        "mode": info.get("mode"),
        "kdf": info.get("kdf"),
        "kdf_params": info.get("kdf_params", {}),
        "has_salt": bool(info.get("salt")),
        "chunks": info.get("chunks", []),
    }
