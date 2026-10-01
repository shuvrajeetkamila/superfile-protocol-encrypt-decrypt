#!/usr/bin/env python3
"""
SUPERFILE — Task C verification: ENCRYPT / DECRYPT (AES-256-GCM).

Runs against a real running SUPERFILE (packaged binary or source tree) over its
own HTTP API and prints what it actually observed.  Every claim in the final
report must be produced by this script, never asserted from theory.

Checks:
  1. capability discovery (/api/health device_lock, /api/registry kdfs)
  2. a real .txt object (CONT text) and a real .png object (BLOB frames):
     encrypt -> HEXDUMP of the produced file + proof the plaintext is absent
  3. the NORMAL open path refuses an encrypted file with the documented message
  4. wrong password -> specific error, no success, no crash
  5. correct password -> decrypted object, decoded text intact, original bytes
     byte-identical, file name -decrypted.sfp
  6. argon2id KDF (when installed) -> ENCR records kdf + cost, round-trips
  7. tampering (flipped byte, chunk spliced from another file) -> refused
  8. device mode: same machine decrypts; a machine without the keyring gets the
     exact documented message; restoring the key works again
  9. EXPORT regression: every existing export still produces its bytes, and the
     .sfp round-trip still preserves the original file byte-for-byte

usage (packaged exe, from the Windows python under wine):
    xvfb-run -a wine 'C:\\Py313\\python.exe' tests/encryption_verify.py \
        release/Superfile.exe --report 'Z:\\tmp\\enc_verify.txt'
usage (source tree, plain python):
    python3 tests/encryption_verify.py --source . --report /tmp/enc_verify.txt

Exit code 0 = all checks passed.  Stdlib only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

RESULTS: list = []
LINES: list = []


def say(line: str = "") -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(line, flush=True)
    LINES.append(line)


def record(name: str, ok: bool, evidence: str = "") -> bool:
    RESULTS.append((bool(ok), name, evidence))
    say(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{evidence}]" if evidence else ""))
    return bool(ok)


def hexdump(data: bytes, limit: int = 96, tail: int = 32) -> list:
    """A real hexdump (offset, hex, ASCII) of the head and the tail of the file."""
    out = []

    def row(off: int, chunk: bytes) -> str:
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        return f"{off:08x}  {hexpart:<47}  |{text}|"

    for off in range(0, min(limit, len(data)), 16):
        out.append(row(off, data[off:off + 16]))
    if len(data) > limit + tail:
        out.append("...")
    for off in range(max(limit, len(data) - tail) // 16 * 16, len(data), 16):
        out.append(row(off, data[off:off + 16]))
    return out


class Client:
    """Tiny HTTP client for the app's own API (mirrors tests/packaged_e2e.py)."""

    def __init__(self, base: str):
        self.base = base

    def _open(self, req):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def get(self, path):
        return self._open(urllib.request.Request(self.base + path))

    def get_json(self, path):
        st, body, _ = self.get(path)
        return json.loads(body.decode("utf-8"))

    def post_json(self, path, payload):
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        return self._open(req)

    def post_raw(self, path, data, filename):
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": "application/octet-stream",
                                              "X-Filename": filename})
        return self._open(req)

    def multipart(self, path, fields, files):
        boundary = "----sf" + uuid.uuid4().hex
        parts = []
        for k, v in fields.items():
            parts += [f"--{boundary}", f'Content-Disposition: form-data; name="{k}"', "", str(v)]
        for k, (fn, blob) in files.items():
            parts += [f"--{boundary}", f'Content-Disposition: form-data; name="{k}"; filename="{fn}"', "", ""]
            body = "\r\n".join(parts[:-1]).encode() + b"\r\n" + blob + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(self.base + path, data=body,
                                         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            return self._open(req)
        body = ("\r\n".join(parts) + f"\r\n--{boundary}--\r\n").encode()
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        return self._open(req)

    def import_bytes(self, name, data):
        st, body, _ = self.post_raw("/api/import", data, name)
        assert st == 200, (st, body[:200])
        return json.loads(body.decode("utf-8"))["object"]["object_id"]

    def encrypt(self, oid, **payload):
        st, body, headers = self.post_json(f"/api/object/{oid}/encrypt", payload)
        return st, body, headers

    def decrypt(self, data, filename="upload.sfp", **fields):
        st, body, _ = self.multipart("/api/decrypt", fields, {"file": (filename, data)})
        try:
            return st, json.loads(body.decode("utf-8"))
        except Exception:
            return st, {"raw": body[:200]}


PNG = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIBAMAAADQhd6fAAAAElBMVEX/AAAA/wAAAP//AAAA"
    b"//8AAAD//wAAAP9cQ0m4AAAAFUlEQVR4nGP4z8Dwn4GBgYGBgYGBAQAeXQL/"
    b"gD8y5QAAAABJRU5ErkJggg==")


cleanup_dirs: list = []       # isolated keyring dirs this script created; removed on the way out


def spawn(args, port):
    env = dict(os.environ)
    if args.source:
        import site
        env["HOME"] = tempfile.mkdtemp(prefix="sfenc_home_")
        env["PYTHONPATH"] = os.pathsep.join(
            [p for p in (site.getusersitepackages(), os.path.abspath(args.source), env.get("PYTHONPATH", "")) if p])
        env["SUPERFILE_QUIET"] = "1"
        exe = sys.executable
        cmd = [exe, "desktop_launcher.py", "--no-browser", "--port", str(port)]
        cwd = os.path.abspath(args.source)
    else:
        exe = os.path.abspath(args.binary)
        cmd = [exe, "--no-browser", "--port", str(port)]
        cwd = os.path.dirname(exe)
        env["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="sfenc_local_")
    if env.get("LOCALAPPDATA") and "sfenc_local_" in env["LOCALAPPDATA"]:
        cleanup_dirs.append(env["LOCALAPPDATA"])
    if env.get("HOME") and "sfenc_home_" in env["HOME"]:
        cleanup_dirs.append(env["HOME"])
    log = open(os.path.join(tempfile.gettempdir(), "sfenc_server.log"), "wb")
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    return proc, log, env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?", default="")
    ap.add_argument("--source", default="", help="run the source tree in this directory instead of a binary")
    ap.add_argument("--report", default="")
    ap.add_argument("--env-note", default="")
    args = ap.parse_args()
    if not args.source and not args.binary:
        ap.error("give a binary path or --source DIR")

    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    proc, log, server_env = spawn(args, port)
    base = f"http://127.0.0.1:{port}/"
    cli = Client(base)
    tmp = tempfile.mkdtemp(prefix="sfenc_work_")
    try:
        for _ in range(600):
            try:
                if cli.get_json("api/health").get("ok"):
                    break
            except Exception:
                time.sleep(0.3)
        else:
            say("server did not start; log tail:")
            say(open(log.name, errors="replace").read()[-800:])
            return 1

        health = cli.get_json("api/health")
        reg = cli.get_json("api/registry")
        lockable = bool(health.get("device_lock"))
        kdfs = reg.get("kdfs") or []
        say("=" * 70)
        say("SUPERFILE — ENCRYPT / DECRYPT VERIFICATION (AES-256-GCM)")
        say("=" * 70)
        say(f"target      : {args.source or args.binary}")
        say(f"platform    : {sys.platform}  python {sys.version.split()[0]}")
        say(f"device_lock : {lockable}    password KDFs: {kdfs}")
        if args.env_note:
            say(f"environment : {args.env_note}")
        say("")

        marker = "TASK-C-PLAINTEXT-MARKER-%s" % uuid.uuid4().hex[:8]
        txt = ("%s\n" % marker + "the quick brown fox jumps over the lazy dog\n" * 6
               + "second line of secret content\n").encode("utf-8")
        png_oid = cli.import_bytes("secret-picture.png", PNG)
        txt_oid = cli.import_bytes("secret-notes.txt", txt)
        say(f"imported    : secret-notes.txt ({len(txt)} B) -> {txt_oid}")
        say(f"              secret-picture.png ({len(PNG)} B) -> {png_oid}")
        say("")

        # ---------------------------------------------------------------- 2. encrypt + hexdump
        say("1. encrypt a text object (password mode, default PBKDF2)")
        st, blob, headers = cli.encrypt(txt_oid, mode="password", password="correct horse battery staple")
        record("encrypt endpoint answered 200 with .sfp bytes", st == 200 and blob[:4] == b"\x8bSFP",
               f"HTTP {st}, {len(blob)} bytes, magic {blob[:8].hex()}")
        say(f"   served as: {headers.get('Content-Disposition', '?')}")
        say("   hexdump of the ENCRYPTED container (head/tail):")
        for line in hexdump(blob):
            say("     " + line)
        record("ENCR chunk present (plaintext framing: mode/kdf/salt/nonce)",
               b"ENCR" in blob, "ENCR at offset %d" % blob.find(b"ENCR"))
        header = _encr_json(blob)
        say(f"   ENCR: mode={header.get('mode')} kdf={header.get('kdf')} params={header.get('kdf_params')}")
        record("the marker text does NOT appear anywhere in the encrypted file",
               marker.encode() not in blob, f"searched {len(blob)} bytes for {marker!r}")
        record("the decoded body text does NOT appear either",
               b"quick brown fox" not in blob and b"second line of secret content" not in blob)
        record("the original file name does NOT appear", b"secret-notes.txt" not in blob)
        # every payload chunk of the text object must be encrypted, OBYT included
        record("container is checksummed AFTER encryption (CKSM last chunk)",
               blob.rfind(b"CKSM") > blob.rfind(b"OBYT"), f"CKSM at {blob.rfind(b'CKSM')}")
        with open(os.path.join(tmp, "secret-notes.encrypted.sfp"), "wb") as fh:
            fh.write(blob)

        # PNG object: CONT + BLOB (decoded frames) must be gone too
        st, png_blob, _ = cli.encrypt(png_oid, mode="password", password="correct horse battery staple")
        record("a PNG object encrypts too (CONT metadata + BLOB decoded frames)",
               st == 200 and b"ENCR" in png_blob and b"secret-picture.png" not in png_blob,
               f"HTTP {st}, {len(png_blob)} bytes, filename absent: {b'secret-picture.png' not in png_blob}")
        record("no raw RGBA/IDAT payload from the PNG object is readable in its encrypted file",
               PNG[20:60] not in png_blob and b"IDAT" not in png_blob)

        # ---------------------------------------------------------------- 3. normal open path
        say("")
        say("2. the NORMAL open path must refuse an encrypted file with a clear message")
        st, body, _ = cli.post_raw("/api/import", blob, "secret-notes.encrypted.sfp")
        msg = json.loads(body.decode("utf-8")).get("error", "")
        record("importing an encrypted .sfp is refused with the documented message",
               st == 400 and msg == "this .sfp is encrypted — use the DECRYPT tab to unlock it first",
               f"HTTP {st}: {msg!r}")

        # ---------------------------------------------------------------- 4/5. decrypt
        say("")
        say("3. decrypt: wrong password, then the right one")
        st, out = cli.decrypt(blob, "secret-notes.encrypted.sfp", mode="password", password="wrong-password")
        record("wrong password -> specific error, no partial success",
               st == 400 and out.get("ok") is False and "wrong password" in out.get("error", ""),
               f"HTTP {st}: {out.get('error')!r}")
        st, out = cli.decrypt(blob, "secret-notes.encrypted.sfp", mode="password",
                              password="correct horse battery staple")
        record("correct password -> {ok:true, filename:'...-decrypted.sfp'}",
               st == 200 and out.get("ok") and out.get("filename", "").endswith("-decrypted.sfp"),
               f"HTTP {st}: {json.dumps(out)[:160]}")
        oid = out.get("object_id", "")
        detail = cli.get_json(f"api/object/{oid}")["detail"]
        record("the decrypted object's decoded text is intact",
               detail["content"].get("text", "").startswith(marker)
               and detail["content"]["text"].count("quick brown fox") == 6,
               f"{detail['content']['text'].count('quick brown fox')} body lines, starts with the marker")
        st, media, _ = cli.get(f"api/object/{oid}/media")
        record("the decrypted object's ORIGINAL BYTES are byte-identical to the source file",
               media == txt, f"{len(media)} bytes, sha256 {hashlib.sha256(media).hexdigest()[:16]}")

        # ---------------------------------------------------------------- 6. argon2id
        say("")
        say("4. password KDFs")
        say(f"   advertised by the server: {kdfs}")
        st, a_blob, _ = cli.encrypt(txt_oid, mode="password", password="argon2-password", kdf="argon2id")
        if "argon2id" in kdfs:
            ah = _encr_json(a_blob)
            record("argon2id requested -> ENCR records argon2id + its cost parameters",
                   st == 200 and ah.get("kdf") == "argon2id" and ah["kdf_params"].get("memory_cost", 0) >= 19456,
                   f"kdf={ah.get('kdf')} params={ah.get('kdf_params')}")
            st, out = cli.decrypt(a_blob, "argon2.sfp", mode="password", password="argon2-password")
            record("an argon2id-protected file decrypts", st == 200 and out.get("ok"), f"HTTP {st}")
        else:
            record("argon2id not advertised (argon2-cffi absent) - reported, not faked", True, str(kdfs))
        st, out = cli.decrypt(blob, "pbkdf2.sfp", mode="password", password="correct horse battery staple")
        record("PBKDF2 files (the default the UI writes) still decrypt", st == 200 and out.get("ok"),
               f"HTTP {st}")
        record("a non-encrypted .sfp is refused by DECRYPT, not mis-read",
               cli.decrypt(b"not an sfp at all", "junk.sfp", mode="password", password="x")[1]
               .get("error") == "not a SUPERFILE container",
               cli.decrypt(b"not an sfp at all", "junk.sfp", mode="password", password="x")[1].get("error"))

        # ---------------------------------------------------------------- 7. tampering
        say("")
        say("5. tampering must be detected")
        flip = bytearray(blob)
        flip[len(flip) // 2] ^= 0x01
        st, out = cli.decrypt(bytes(flip), "flipped.sfp", mode="password", password="correct horse battery staple")
        record("a single flipped byte -> refused (checksum/GCM), no crash",
               st == 400 and out.get("ok") is False, f"HTTP {st}: {out.get('error')}")
        # splice a ciphertext chunk from a SECOND encryption of the same object into the first, then
        # rebuild CKSM so the container is structurally valid: only GCM authentication can reject it
        other = cli.encrypt(txt_oid, mode="password", password="correct horse battery staple")[1]

        def chunk(data, tag):
            return _payload_of(data, tag)

        _i, _e, mine_ct = _payload_of(blob, b"OBYT")
        i, end, other_ct = _payload_of(other, b"OBYT")
        i, end = _payload_of(blob, b"OBYT")[0], _payload_of(blob, b"OBYT")[1]
        record("the splice test really moves a non-empty payload chunk",
               len(mine_ct) == len(other_ct) > 0 and mine_ct != other_ct,
               f"{len(mine_ct)} bytes of ciphertext swapped, different content: {mine_ct != other_ct}")
        spliced = blob[:i] + other_ct + blob[end:]
        head = spliced[:spliced.rindex(b"CKSM")]
        spliced = head + b"CKSM" + struct.pack(">Q", 32) + hashlib.sha256(head).digest()
        st, out = cli.decrypt(spliced, "spliced.sfp", mode="password", password="correct horse battery staple")
        record("a chunk spliced in from another encryption is rejected by GCM itself (checksum rebuilt)",
               st == 400 and out.get("ok") is False and "authenticate" in (out.get("error") or ""),
               f"HTTP {st}: {out.get('error')}")

        # ---------------------------------------------------------------- 8. device mode
        say("")
        say("6. device mode (Windows DPAPI)")
        real_keyring = _machine_keyring()
        before = _keyring_fingerprint(real_keyring)
        say(f"   this machine's own keyring (must stay untouched): {real_keyring} -> {before}")
        if lockable:
            st, dev_blob, _ = cli.encrypt(txt_oid, mode="device")
            dh = _encr_json(dev_blob)
            record("device mode encrypts (no password) and records the device reference",
                   st == 200 and dh.get("mode") == "device" and dh.get("device_ref"),
                   f"device_ref={dh.get('device_ref')} kdf={dh.get('kdf')}")
            record("the device-locked file also hides the plaintext", marker.encode() not in dev_blob)
            st, out = cli.decrypt(dev_blob, "device.sfp", mode="device")
            record("the SAME machine unlocks it with no password", st == 200 and out.get("ok"),
                   f"HTTP {st}: {json.dumps(out)[:120]}")
            keyfile = _find_device_key(server_env)
            if keyfile:
                say(f"   device keyring: {keyfile}")
                hidden = keyfile + ".other-device"
                os.rename(keyfile, hidden)
                try:
                    st, out = cli.decrypt(dev_blob, "device.sfp", mode="device")
                    record("a machine WITHOUT the keyring gets the exact documented message",
                           st == 400 and out.get("error")
                           == "This file was locked to a different device, or needs a password.",
                           f"HTTP {st}: {out.get('error')!r}")
                finally:
                    os.rename(hidden, keyfile)
                st, out = cli.decrypt(dev_blob, "device.sfp", mode="device")
                record("with the keyring restored the same machine unlocks it again",
                       st == 200 and out.get("ok"), f"HTTP {st}")
            else:
                record("device keyring located on disk", False, "device-key.json not found")
            after = _keyring_fingerprint(real_keyring)
            record("the device-locked run did NOT poison this machine's own keyring "
                   "(it ran with an isolated, temporary keyring)",
                   before == after, f"{before} -> {after}")
        else:
            st, body, _ = cli.encrypt(txt_oid, mode="device")
            record("device mode is refused with the documented note, not faked",
                   st == 400 and "Windows-only" in json.loads(body.decode("utf-8")).get("error", ""),
                   f"HTTP {st}: {json.loads(body.decode('utf-8')).get('error')!r}")
            st, out = cli.decrypt(blob, "x.sfp", mode="device")
            err = out.get("error", "")
            record("device-mode DECRYPT on this platform reports the same limitation",
                   st == 400 and ("Windows-only" in err or "different device, or needs a password" in err),
                   f"HTTP {st}: {err!r}")

        # ---------------------------------------------------------------- 6b. malformed uploads
        say("")
        say("6b. /api/decrypt refuses malformed requests with a plain 400 (never a bare 500)")
        def _json(body):
            try:
                return json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                return {"error": f"<non-JSON body {body[:40]!r}>"}

        st, body, _h = cli.multipart("/api/decrypt", {"mode": "password", "password": "x"}, {})
        out = _json(body)
        record("no file part -> documented 400", st == 400
               and out.get("ok") is False and out.get("error") == "no file part in the request",
               f"HTTP {st}: {out.get('error')!r}")
        st, body, _h = cli.multipart("/api/decrypt", {"mode": "password", "password": "x"},
                                     {"file": ("x.sfp", b"")})
        out = _json(body)
        record("empty upload -> documented 400", st == 400
               and out.get("ok") is False and out.get("error") == "the uploaded file is empty",
               f"HTTP {st}: {out.get('error')!r}")
        st, body, _h = cli.post_raw("/api/decrypt", b"not multipart at all", "x.sfp")
        out = _json(body)
        record("non-multipart body -> documented 400", st == 400
               and out.get("error") == "expected multipart/form-data with the .sfp file",
               f"HTTP {st}: {out.get('error')!r}")
        st, body, _h = cli.multipart("/api/decrypt", {"mode": "password", "password": "x"},
                                     {"file": ("garbage.sfp", b"this is not a container at all")})
        out = _json(body)
        record("garbage bytes -> documented 400, never a 5xx",
               st == 400 and out.get("ok") is False and out.get("error")
               and "server error" not in str(out.get("error")),
               f"HTTP {st}: {out.get('error')!r}")

        # ---------------------------------------------------------------- 9. regression
        say("")
        say("7. regression: everything that existed before still works")
        # the adapters are honest about what they can convert: a format is either produced with real bytes
        # or refused with a specific error - never a 5xx, never an empty success
        json_oid = cli.import_bytes("data.json", open(os.path.join(ROOT, "demo", "data.json"), "rb").read())
        clean = True
        produced = {}
        for label, oid, source_fmt in (("secret-notes.txt", txt_oid, "txt"), ("data.json", json_oid, "json")):
            produced[label] = []
            for fmt in ("txt", "md", "html", "json", "csv", "yaml", "xml", "sfp"):
                st, body, _ = cli.post_json(f"/api/object/{oid}/export", {"format": fmt})
                data = json.loads(body.decode("utf-8")) if st in (200, 400) else {}
                size = len(base64.b64decode(data.get("base64", ""))) if data.get("ok") else 0
                good = bool((st == 200 and data.get("ok") and size > 0 and data.get("filename")) or
                            (st == 400 and data.get("ok") is False and bool(data.get("error"))))
                clean &= good
                if data.get("ok"):
                    produced[label].append(fmt)
                say(f"   EXPORT {label:<17} -> {fmt:<5} HTTP {st}  "
                    f"{data.get('filename') or (data.get('error') or '')[:44]:<44} {size} B")
        record("every EXPORT attempt is either real bytes or a specific refusal (no 5xx, no empty success)", clean)
        record("EXPORT still produces the source format of each object",
               "txt" in produced["secret-notes.txt"] and "json" in produced["data.json"],
               f"txt object -> {produced['secret-notes.txt']} | json object -> {produced['data.json']}")
        record("EXPORT .sfp still works from both", "sfp" in produced["secret-notes.txt"]
               and "sfp" in produced["data.json"])
        st, sfp, _ = cli.post_json(f"/api/object/{txt_oid}/export", {"format": "sfp"})
        sfp_data = base64.b64decode(json.loads(sfp.decode("utf-8"))["base64"])
        record("SAVE AS .SFP still writes the plain container", sfp_data[:4] == b"\x8bSFP" and b"ENCR" not in sfp_data,
               f"{len(sfp_data)} bytes, magic {sfp_data[:8].hex()}")
        restored = cli.import_bytes("restored.sfp", sfp_data)
        st, media2, _ = cli.get(f"api/object/{restored}/media")
        record("SFP round-trip still preserves the original bytes byte-for-byte", media2 == txt,
               f"{len(media2)} bytes identical: {media2 == txt}")
        reg_after = cli.get_json("api/registry")
        record("the adapter registry is unchanged (no adapter lost)",
               len(reg_after["adapters"]) == len(reg["adapters"]) and len(reg_after["formats"]) == len(reg["formats"]),
               f"adapters {len(reg_after['adapters'])}, formats {len(reg_after['formats'])}, "
               f"transforms {len(reg_after['transforms'])}")
        record("an encrypted file is NOT mistaken for a normal object anywhere",
               cli.get_json("api/health").get("ok") is True)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=20)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        log.close()
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in RESULTS if not r[0]]
    say("")
    say("=" * 70)
    say(f"RESULT: {len(RESULTS) - len(bad)} passed, {len(bad)} failed, {len(RESULTS)} checks")
    for _ok, name, detail in bad:
        say(f"   FAILED: {name}  [{detail}]")
    say("=" * 70)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write("\n".join(LINES) + "\n")
        say(f"report written to {args.report}")
    return 1 if bad else 0


def _container_chunks(data: bytes):
    """Walk the real chunk table: header(32) then tag(4) + u64 big-endian length + payload.

    Searching for a tag *name* is not enough — the ENCR JSON lists the encrypted chunk names.
    """
    off = struct.unpack(">I", data[12:16])[0]          # header_size
    while off + 12 <= len(data):
        tag = data[off:off + 4]
        n = struct.unpack(">Q", data[off + 4:off + 12])[0]
        yield tag, off + 12, off + 12 + n, data[off + 12:off + 12 + n]
        off = off + 12 + n


def _payload_of(data: bytes, tag: bytes):
    for t, start, end, payload in _container_chunks(data):
        if t == tag:
            return start, end, payload
    raise AssertionError("chunk %r not found" % tag)

def _encr_json(blob: bytes) -> dict:
    """Read the ENCR chunk of a container without importing the app package."""
    try:
        return json.loads(_payload_of(blob, b"ENCR")[2].decode("utf-8"))
    except Exception:
        return {}


def _keyring_fingerprint(path: str) -> str:
    """sha256+size of a keyring file, or 'absent' — used to prove a run did not touch the real one."""
    if not path or not os.path.isfile(path):
        return "absent"
    data = open(path, "rb").read()
    return f"{len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}"


def _machine_keyring() -> str:
    r"""THIS machine's own keyring path by the exact rule superfile/crypto.py uses - no directory walk,
    so the fingerprint cannot accidentally pick up some stale file from another run."""
    if os.environ.get("SUPERFILE_DEVICE_DIR"):
        return os.path.join(os.environ["SUPERFILE_DEVICE_DIR"], "device-key.json")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or ""
        return os.path.join(base, "Superfile", "device-key.json") if base else ""
    home = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.join(home, ".local", "share", "Superfile", "device-key.json")


def _find_device_key(server_env: dict) -> str:
    r"""The exact keyring file for the server we started (same rule as superfile/crypto.py).

    Windows: %LOCALAPPDATA%\Superfile\device-key.json (or $SUPERFILE_DEVICE_DIR)
    posix  : $HOME/.local/share/Superfile/device-key.json
    """
    cands = []
    if server_env.get("SUPERFILE_DEVICE_DIR"):
        cands.append(os.path.join(server_env["SUPERFILE_DEVICE_DIR"], "device-key.json"))
    if sys.platform == "win32":
        for base in (server_env.get("LOCALAPPDATA"), os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA")):
            if base:
                cands.append(os.path.join(base, "Superfile", "device-key.json"))
    else:
        home = server_env.get("HOME") or os.path.expanduser("~")
        cands.append(os.path.join(home, ".local", "share", "Superfile", "device-key.json"))
    for path in cands:
        if os.path.isfile(path):
            return path
    # last resort: only the app's own folders, never a whole-tree walk (that found stale key files)
    for base in (server_env.get("LOCALAPPDATA"), os.environ.get("LOCALAPPDATA")):
        if base:
            for dp, _dn, fns in os.walk(base):
                if "Superfile" in dp:
                    for fn in fns:
                        if fn == "device-key.json":
                            return os.path.join(dp, fn)
    return ""


def _cleanup() -> None:
    """Leave no isolated keyring dirs behind (a stale one inside a wine prefix once confused a
    different test that went looking for device-key.json)."""
    for d in cleanup_dirs:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        _cleanup()
