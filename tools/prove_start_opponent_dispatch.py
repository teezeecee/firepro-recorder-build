#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import io
import json
import struct
import zipfile
import zlib
from collections import Counter
from pathlib import Path

DLL_SHA = "9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA = "93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA = "79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
METHOD_RVA = 0x002DABA8
METHOD_CODE_SIZE = 905
METHOD_CODE_SHA = "4b390293560fe3a02b12845d80419fe4d8747c637a3c94221cf2dac051ffb2cb"
MAGIC = b"R6SO1"
CHILDREN = {
    "FormAnimator.ReqSerialAnm",
    "FormAnimator.ReqSkillAnm",
    "FormAnimator.ReqBasicAnm",
    "FormAnimator.ReqSlotAnm",
}

class ProofError(RuntimeError):
    pass

def sha256_path(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_stream(f):
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
    return h.hexdigest()

def rva_to_offset(pe, rva):
    peoff = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[peoff:peoff+4] != b"PE\0\0":
        raise ProofError("not a PE file")
    nsec = struct.unpack_from("<H", pe, peoff + 6)[0]
    optsz = struct.unpack_from("<H", pe, peoff + 20)[0]
    sec = peoff + 24 + optsz
    for i in range(nsec):
        o = sec + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", pe, o + 8)
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va)
    raise ProofError(f"RVA not mapped: {rva:#x}")

def method_code(pe, rva):
    off = rva_to_offset(pe, rva)
    b = pe[off]
    if b & 3 == 2:
        header = 1
        size = b >> 2
    elif b & 3 == 3:
        flags_size = struct.unpack_from("<H", pe, off)[0]
        header = (flags_size >> 12) * 4
        size = struct.unpack_from("<I", pe, off + 4)[0]
    else:
        raise ProofError(f"bad IL method header at {rva:#x}")
    return pe[off + header:off + header + size]

def u32le(b, off):
    return struct.unpack_from("<I", b, off)[0]

def verify_dll(path):
    got = sha256_path(path)
    if got != DLL_SHA:
        raise ProofError(f"DLL SHA mismatch: {got}")
    pe = Path(path).read_bytes()
    code = method_code(pe, METHOD_RVA)
    if len(code) != METHOD_CODE_SIZE:
        raise ProofError(f"StartOpponentAnm code size mismatch: {len(code)}")
    code_sha = hashlib.sha256(code).hexdigest()
    if code_sha != METHOD_CODE_SHA:
        raise ProofError(f"StartOpponentAnm code SHA mismatch: {code_sha}")
    checks = [
        (6, 0x6F, 0x06005065, "PlayerMan.GetPlObj"),
        (36, 0x7B, 0x04005ECF, "FormAnimator.AnmReqType"),
        (59, 0x6F, 0x06004E6D, "FormAnimator.ReqSerialAnm"),
        (70, 0x7B, 0x04005ECF, "FormAnimator.AnmReqType"),
        (93, 0x6F, 0x06004E6E, "FormAnimator.ReqSkillAnm"),
        (104, 0x7B, 0x04005ECF, "FormAnimator.AnmReqType"),
        (128, 0x6F, 0x06004E6F, "FormAnimator.ReqBasicAnm"),
        (153, 0x6F, 0x06004E70, "FormAnimator.ReqSlotAnm"),
    ]
    for off, opcode, token, label in checks:
        if code[off] != opcode or u32le(code, off + 1) != token:
            raise ProofError(f"IL token check failed at +0x{off:X} ({label})")
    if code[5] != 0x03:
        raise ProofError("StartOpponentAnm no longer loads arg1 before GetPlObj")
    if code[41] != 0x18 or code[75] != 0x19:
        raise ProofError("AnmReqType dispatch constants changed")
    if code[109] != 0x3A:
        raise ProofError("AnmReqType zero/nonzero branch changed")
    return {
        "sha256": got,
        "size_bytes": len(pe),
        "method_rva": f"0x{METHOD_RVA:08X}",
        "method_code_size": len(code),
        "method_code_sha256": code_sha,
    }

def put_varint(out, n):
    if n < 0:
        raise ProofError("negative varint")
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return

def encode_lines(records):
    raw = bytearray(MAGIC)
    put_varint(raw, len(records))
    prev = 0
    for rec in records:
        p = rec["parent_pre_line"]
        put_varint(raw, p - prev)
        prev = p
        put_varint(raw, rec["parent_post_line"] - p)
        put_varint(raw, rec["child_pre_line"] - p)
    raw = bytes(raw)
    artifact = base64.b64encode(zlib.compress(raw, 9)) + b"\n"
    return raw, artifact

def verify_r6(path):
    got = sha256_path(path)
    if got != R6_SHA:
        raise ProofError(f"R6 SHA mismatch: {got}")
    records = []
    active = None
    method_counts = Counter()
    slot_equal = 0
    owner_equal = 0
    source_counts = Counter()
    pre_count = post_count = 0

    with zipfile.ZipFile(path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise ProofError(f"R6 ZIP CRC failure: {bad}")
        names = [n for n in zf.namelist() if Path(n).name == "event_trace.tsv"]
        if len(names) != 1:
            raise ProofError(f"expected one event_trace.tsv, found {len(names)}")
        event_name = names[0]
        with zf.open(event_name) as f:
            event_sha = sha256_stream(f)
        if event_sha != EVENT_SHA:
            raise ProofError(f"event_trace SHA mismatch: {event_sha}")

        with zf.open(event_name) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""), delimiter="\t")
            for line, row in enumerate(reader, start=2):
                method = row["method"]
                phase = row["phase"]
                if method == "FormAnimator.StartOpponentAnm":
                    if phase == "PRE":
                        pre_count += 1
                        if active is not None:
                            raise ProofError("overlapping StartOpponentAnm calls in R6")
                        active = {"parent_pre_line": line, "pre": row, "children": []}
                    elif phase == "POST":
                        post_count += 1
                        if active is None or active["pre"]["instance"] != row["instance"]:
                            raise ProofError(f"unmatched StartOpponentAnm POST at line {line}")
                        if len(active["children"]) != 1:
                            raise ProofError(f"parent at line {active['parent_pre_line']} has {len(active['children'])} nested requests")
                        child_line, child = active["children"][0]
                        args = [x.strip() for x in active["pre"]["args"].split("|")]
                        if len(args) != 2:
                            raise ProofError(f"bad StartOpponentAnm args at line {active['parent_pre_line']}")
                        arg1 = int(args[0])
                        parent_target = int(active["pre"]["target"])
                        child_owner = int(child["owner_slot"])
                        if arg1 != parent_target or parent_target != child_owner:
                            raise ProofError(f"ownership mismatch at parent line {active['parent_pre_line']}")
                        owner_equal += 1
                        method_counts[child["method"]] += 1
                        if child["method"] == "FormAnimator.ReqSlotAnm":
                            if not active["pre"]["ResolvedSkillID"] or active["pre"]["ResolvedSkillID"] != child["ResolvedSkillID"]:
                                raise ProofError(f"ResolvedSkillID mismatch at parent line {active['parent_pre_line']}")
                            slot_equal += 1
                            source_counts[child["ResolvedSkillSource"]] += 1
                        records.append({
                            "parent_pre_line": active["parent_pre_line"],
                            "parent_post_line": line,
                            "child_pre_line": child_line,
                        })
                        active = None
                elif phase == "PRE" and method in CHILDREN and active is not None:
                    active["children"].append((line, row))

    if active is not None:
        raise ProofError("unterminated StartOpponentAnm call")
    expected = Counter({"FormAnimator.ReqBasicAnm": 585, "FormAnimator.ReqSlotAnm": 262})
    if pre_count != 847 or post_count != 847 or len(records) != 847:
        raise ProofError((pre_count, post_count, len(records)))
    if method_counts != expected:
        raise ProofError(f"nested request counts changed: {method_counts}")
    if owner_equal != 847 or slot_equal != 262:
        raise ProofError((owner_equal, slot_equal))
    if source_counts != Counter({"StartOpponentAnm.host_skill": 262}):
        raise ProofError(f"slot source counts changed: {source_counts}")

    decoded, artifact = encode_lines(records)
    return {
        "archive_sha256": got,
        "event_trace_sha256": EVENT_SHA,
        "start_opponent_pre": pre_count,
        "start_opponent_post": post_count,
        "nested_request_counts": dict(method_counts),
        "ownership_equal_count": owner_equal,
        "slot_skill_equal_count": slot_equal,
        "slot_skill_source_counts": dict(source_counts),
        "witness_artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "witness_decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "witness_artifact_text": artifact.decode("ascii"),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--r6", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    try:
        result = {"dll": verify_dll(a.dll), "r6": verify_r6(a.r6)}
        artifact_text = result["r6"].pop("witness_artifact_text")
        if a.out:
            Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            Path(a.out + ".witness.b64").write_text(artifact_text, encoding="ascii")
        print(json.dumps(result, indent=2, sort_keys=True))
        print("PROVE_START_OPPONENT_DISPATCH: PASS")
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, ProofError) as e:
        print("PROVE_START_OPPONENT_DISPATCH: FAIL")
        print(str(e))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
