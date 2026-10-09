#!/usr/bin/env python3
"""Replay FACT-0266 against original DLL and optionally parent-unverified export."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_parse_rsf_prefix.summary.json"
def check(x,s):
 if not x:raise RuntimeError(s)
def prove(dll,w):
 pe=Path(dll).read_bytes()
 check(len(pe)==w["dll_size"] and hashlib.sha256(pe).hexdigest()==w["dll_sha256"],"DLL source identity")
 ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
 sb=st["#Strings"][0];bb=st["#Blob"][0];fm,mm=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,mm,0x0600525f);m=w["parser"]
 check((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"raw MethodDef")
 check(pe[base.off(ss,md[1]):md[8]].hex()==m["header_hex"],"IL header")
 body=md[9];check(len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"complete IL method SHA")
 check(body[:0x1b].hex()==m["entry_hex"],"source parser entry")
 check(body[0x1b:0x45].hex()==m["cursor_skip_hex"],"ten unsigned-byte cursor increments")
 initial=body[0x1d:0x45]
 step=bytes.fromhex(w["parser"]["cursor_derivation"]["advance_pattern_hex"])
 check(len(initial)==10*len(step) and initial==step*10,"exact ten cursor increments")
 check(m["byte_field_sites"][0]["relative_offset"]==10 and m["byte_field_sites"][1]["relative_offset"]==11,"source-relative offsets match cursor")
 for n,field in enumerate(m["byte_field_sites"]):
  at=int(field["il"],16)
  check(field["relative_offset"]==10+n and body[at+1:at+8].hex()==w["parser"]["cursor_derivation"]["read_pattern_hex"],"byte read uses old cursor then updates local")
  check(body[at:at+13].hex()==field["hex"],"source byte and field store "+field["field"])
  f=base.field(pe,s,b,z,o,sb,bb,fm,int(field["token"],16))
  check((f[0],f[2])==(field["row_hex"],field["field"]),"FieldDef name/bytes "+field["token"])
 for tok,n in [(0x06001164,"GetSkillInfo"),(0x0600524c,".ctor")]:
  mmr=base.method(pe,ss,s,b,ix,z,o,sb,bb,mm,tok)
  check(mmr[4]==n,"original target "+n)
 pmd=base.method(pe,ss,s,b,ix,z,o,sb,bb,mm,0x06005257);parent=w["loader_guard"]
 check(hashlib.sha256(pmd[9]).hexdigest()==parent["code_sha256"],"original source guard method")
 check(pmd[9][0x30:0x3e].hex()==parent["hex"] and struct.unpack_from("<i",pmd[9],0xb1)[0]==4188,"source early exit and upper bound")
 return {"dll":"PASS","parser_il_bytes":len(body),"first_byte_field_offsets":[x["relative_offset"] for x in m["byte_field_sites"]],"loader_bound":4188}
def exported(path,w):
 e=w["quarantined_export_observation"];raw=Path(path).read_bytes()
 check(len(raw)==e["size"] and hashlib.sha256(raw).hexdigest()==e["raw_sha256"],"export identity")
 s=e["script_start"];ln=struct.unpack_from("<I",raw,12)[0]
 check(ln==e["script_length"] and s+ln+4==len(raw) and raw[s+ln:]==bytes(4),"TextAsset wrapper")
 buf=raw[s:s+ln];check(hashlib.sha256(buf).hexdigest()==e["script_sha256"],"export payload")
 first=struct.unpack_from("<I",buf,0)[0]
 check(first==e["first_offset"] and first%8==0 and first//8==e["index_pair_count"],"indexed region")
 n=zero=pop=0
 for i in range(first//8):
  off,length=struct.unpack_from("<II",buf,i*8)
  if off>=ln:
   check(i==e["first_offset_ge_length_index"] and off==e["first_offset_ge_length_value"] and length==0,"terminator")
   break
  check(off>=0,"signed positive offset")
  if length:
   check(off+length<=ln and buf[off:off+2]==b"RS" and struct.unpack_from("<I",buf,off+2)[0]==length,"bounded RS record")
   pop+=1
  else:zero+=1
  n+=1
 else:raise RuntimeError("no terminator")
 check((n,pop,zero)==(3875,e["populated_before_stop"],e["zero_length_before_stop"]),"conditional export counts")
 return {"export_status":e["source_status"],"would_exit_at_index":n,"populated":pop,"empty_before_terminator":zero}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--fprwaza-export");a=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"));check(w["source_ids"]==["DLL-001"],"source scope")
  out=prove(a.dll,w)
  if a.fprwaza_export:out["conditional_export"]=exported(a.fprwaza_export,w)
  print(json.dumps(out,indent=2,sort_keys=True));print("PROVE_SKILL_DATA_MAN_PARSE_RSF_PREFIX: PASS");return 0
 except Exception as err:
  print("PROVE_SKILL_DATA_MAN_PARSE_RSF_PREFIX: FAIL",str(err));return 1
if __name__=="__main__":raise SystemExit(main())
