#!/usr/bin/env python3
"""FACT-0317 exact original DLCManager static DLCNums initializer and FieldRVA bytes."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_manager_static_dlcnums_source.summary.json"
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"exact original retail DLL")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"original .cctor MethodDef/owner")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original method header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"exact full original 24-byte IL")
    ck(il[:2]==bytes([0x1F,0x0D]) and il[7:8]==bytes([0x25]) and il[23:]==bytes([0x2A]),"exact 13-length/dup/ret IL")
    typ=w["array_type"];tm=p.typedef(pe,rows,s,ix,z,o,sb,int(typ["token"],16)&0xffffff)
    ck(tm[:3]==(typ["row"],typ["name"],typ["namespace"]),"original DLCEnum TypeDef")
    ck(il[2:7]==bytes([int(typ["opcode"],16)])+struct.pack("<I",int(typ["token"],16)),"original newarr DLCEnum")
    for key in ("initializer_field","target_field"):
        fld=w[key];tok=int(fld["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,tok)==(fld["row"],(fld["owner"],fld["namespace"]),fld["name"],fld["signature"]),"original FieldDef owner and signature "+key)
        at=fld["site"];ck(il[at:at+5]==bytes([int(fld["opcode"],16)])+struct.pack("<I",tok),"original FieldDef IL operand "+key)
    mr=w["initialize_array"];tok=int(mr["token"],16)
    rr=int(mr["owner_type_token"],16)&0xffffff;at=o[1]+(rr-1)*z[1]
    tref=pe[at:at+z[1]];coded,at=p.rd(pe,at,z[1]-2*s);ni,at=p.rd(pe,at,s);nsi,at=p.rd(pe,at,s)
    ck((tref.hex(),p.s_at(pe,sb,ni),p.s_at(pe,sb,nsi))==(mr["type_ref_row"],mr["owner_name"],mr["owner_namespace"]),"exact RuntimeHelpers TypeRef")
    at=o[10]+((tok&0xffffff)-1)*z[10];raw=pe[at:at+z[10]]
    cc,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
    ck((raw.hex(),cc,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(mr["member_row"],mr["member_class_coded"],mr["name"],mr["member_signature"]),"original InitializeArray MemberRef")
    ck((cc&7)==1 and (0x01000000|(cc>>3))==int(mr["owner_type_token"],16),"original MemberRef owner TypeRef")
    at=mr["site"];ck(il[at:at+5]==bytes([int(mr["opcode"],16)])+struct.pack("<I",tok),"original InitializeArray call site")
    def ti(n):return 4 if rows.get(n,0)>=65536 else 2
    def cx(ts,k):return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-k)) else 2
    widths={18:ti(2)+ti(20),19:ti(20),20:2+s+cx([2,1,27],2),21:ti(2)+ti(23),22:ti(23),23:2+s+b,24:2+ti(6)+cx([20,23],1),25:ti(2)+2*cx([6,10],1),26:s,27:b,28:2+cx([4,6],1)+s+ti(26),29:4+ti(4)}
    ck(17 in o and 29 in rows,"original metadata table presence")
    at=o[17]+rows[17]*z[17]
    for t in range(18,29):
        if t in rows:at+=rows[t]*widths[t]
    entry=w["field_rva"];matches=[]
    for j in range(rows[29]):
        loc=at+j*widths[29];rva=struct.unpack_from("<I",pe,loc)[0]
        fld=int.from_bytes(pe[loc+4:loc+widths[29]],"little")
        if fld==(int(entry["field_token"],16)&0xffffff):
            matches.append((pe[loc:loc+widths[29]].hex(),rva))
    ck(matches==[(entry["row"],int(entry["rva"],16))],"exact unique original FieldRVA record")
    raw=pe[p.off(ss,int(entry["rva"],16)):p.off(ss,int(entry["rva"],16))+entry["byte_length"]]
    ck((len(raw),raw.hex(),hashlib.sha256(raw).hexdigest())==(entry["byte_length"],entry["raw_hex"],entry["raw_sha256"]),"exact 52-byte original initialized data")
    ids=list(struct.unpack("<"+"i"*w["array_new_count"],raw))
    ck(ids==entry["raw_int32_le"] and len(ids)==13,"original ordered DLCEnum raw integer array")
    return {"fact":"FACT-0317","original_dll_source":"PASS","raw_dlcnums_count":len(ids),"raw_dlcnums_sha256":entry["raw_sha256"],"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"));ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_MANAGER_STATIC_DLCNUMS_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_DLC_MANAGER_STATIC_DLCNUMS_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_MANAGER_STATIC_DLCNUMS_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
