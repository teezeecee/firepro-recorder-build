#!/usr/bin/env python3
"""FACT-0300: independent raw original DLL source checks for two shared-IL helpers."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_attack_defense_param_parser_source.summary.json"
PARENT_TOKEN=0x06001153
PARENT_SHA="96f871227fbcdc6b6851eb5e15fb221dfe1a9a4b58693ea8961f5c5156c0c95b"
SIBLING_TOKEN=0x0600115A
def check(ok,label):
    if not ok: raise AssertionError(label)
def verify(dll_path,w):
    raw=Path(dll_path).read_bytes()
    check(len(raw)==w["dll"]["size_bytes"] and hashlib.sha256(raw).hexdigest()==w["dll"]["sha256"],"original DLL identity")
    sec,q=p.secs(raw)
    streams,heap_sizes,rows,pos=p.mdstreams(raw,sec,q)
    str_sz,blob_sz,ix,table_sz,offsets=p.tables(raw,streams,heap_sizes,rows,pos)
    strings=streams["#Strings"][0]; blobs=streams["#Blob"][0]
    fields,owners=p.owner_maps(raw,rows,str_sz,ix,table_sz,offsets,strings)
    parent=p.method(raw,sec,str_sz,blob_sz,ix,table_sz,offsets,strings,blobs,owners,PARENT_TOKEN)
    pb=parent[9]
    check(len(pb)==1396 and hashlib.sha256(pb).hexdigest()==PARENT_SHA,"original parent full IL")
    sibling=p.method(raw,sec,str_sz,blob_sz,ix,table_sz,offsets,strings,blobs,owners,SIBLING_TOKEN)[9]
    check(len(sibling)==w["body"]["length"] and hashlib.sha256(sibling).hexdigest()==w["body"]["sha256"],"original FACT-0298 source sibling")
    expected=bytes.fromhex(w["body"]["hex"])
    check(len(expected)==w["body"]["length"] and hashlib.sha256(expected).hexdigest()==w["body"]["sha256"],"witness full 71-byte IL")
    check(expected==sibling,"exact original sibling source")
    seen=[]
    for m in w["methods"]:
        tok=int(m["token"],16)
        v=p.method(raw,sec,str_sz,blob_sz,ix,table_sz,offsets,strings,blobs,owners,tok)
        check((v[0],v[1],v[4],v[5],v[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original method metadata "+m["name"])
        check(raw[p.off(sec,v[1]):v[8]].hex()==m["header"],"original fat header "+m["name"])
        check(v[9]==expected,"complete matching IL "+m["name"])
        eh_pos=(v[8]+len(v[9])+3)&~3
        check(raw[eh_pos:eh_pos+16].hex()==w["exception"]["hex"],"original small catch section "+m["name"])
        clause=raw[eh_pos:eh_pos+16]
        check(clause[0]==1 and clause[1]==16 and struct.unpack_from("<H",clause,6)[0]==w["exception"]["try_offset"],"original catch structure")
        check(w["exception"]["try_offset"]==40 and 16<40,"Substring first outside catch")
        token_bytes=struct.pack("<I",tok)
        positions=[i for i in range(len(pb)-4) if pb[i:i+5]==b"\x28"+token_bytes]
        check(positions==m["parent_call_sites"],"original direct caller positions "+m["name"])
        seen.extend(positions)
    check(sorted(seen)==[280,298,316,334],"four unique direct source caller sites")
    check(expected[1:6]==bytes.fromhex("281500000a"),"source IsNullOrEmpty call")
    check(expected[13:21]==bytes.fromhex("0218176f1800000a"),"first Substring(2,1)")
    check(expected[21:26]==bytes.fromhex("726f040070"),"source space literal token")
    check(expected[40:48]==bytes.fromhex("0216186f1800000a"),"second Substring(0,2)")
    check(expected[48:53]==bytes.fromhex("28de06000a"),"source Int32.Parse")
    check(raw[streams["#US"][0]+0x46f:streams["#US"][0]+0x473].hex()=="03200000","original literal-space #US heap")
    return {"fact":"FACT-0300","dll_source":"PASS","helpers":[m["name"] for m in w["methods"]],"parent_calls":sorted(seen),"runtime_unlocked":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_ATTACK_DEFENSE_PARAM_SHARED_IL_V1",["DLL-001"]),"source witness")
        print(json.dumps(verify(args.dll,w),sort_keys=True))
        print("PROVE_SKILL_INFO_MANAGER_ATTACK_DEFENSE_PARAM_PARSER_SOURCE: PASS")
        return 0
    except Exception as exc:
        print("PROVE_SKILL_INFO_MANAGER_ATTACK_DEFENSE_PARAM_PARSER_SOURCE: FAIL",str(exc))
        return 1
if __name__=="__main__": raise SystemExit(main())
