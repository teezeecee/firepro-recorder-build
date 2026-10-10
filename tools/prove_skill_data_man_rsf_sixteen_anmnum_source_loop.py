#!/usr/bin/env python3
"""FACT-0274 prove original RSF 16-int32-element source loop and GetAnmNum assignment."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json"
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];m=d["method"];a=d["window"]
 need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original SHA-pinned DLL identity")
 sections,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,sections,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,sections,s,b,ix,z,o,sb,bb,owners,0x0600525F);body=md[9]
 need((md[0],md[1],md[4],md[7])==(m["row_hex"],int(m["rva"],16),m["name"],(m["owner"],"")),"original ParseRSFData MethodDef")
 need(pe[base.off(sections,md[1]):md[8]].hex()==m["header_hex"] and len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"],"complete original IL")
 start=int(a["start_il"],16);end=int(a["end_exclusive_il"],16)
 need((start,end,end-start)==(0x361,0x39a,57) and hashlib.sha256(body[start:end]).hexdigest()==a["source_sha256"],"exact 57 original IL bytes")
 expected=[
 ("init_int32_array_and_index",0x361,0x36d,"1f108dd7000001130b16130c"),
 ("jump_to_loop_condition",0x36d,0x372,"3812000000"),
 ("old_cursor_unsigned_byte_to_int32_element",0x372,0x37e,"110b110c03082517580c919e"),
 ("increment_iteration_index",0x37e,0x384,"110c1758130c"),
 ("loop_while_less_than_sixteen",0x384,0x38d,"110c1f103fe5ffffff"),
 ("call_original_GetAnmNum_and_store_field",0x38d,0x39a,"07110b28655200067d547c0004")]
 seg=a["segments"];need(len(seg)==len(expected),"six original source spans")
 at=start
 for item,(name,lo,hi,hx) in zip(seg,expected):
  need((item["name"],int(item["start_il"],16),int(item["end_exclusive_il"],16),item["il_hex"])==(name,lo,hi,hx) and lo==at and body[lo:hi]==bytes.fromhex(hx),"exact original IL segment "+name)
  at=hi
 need(at==end and b"".join(bytes.fromhex(x[3]) for x in expected)==body[start:end],"no omitted IL")
 need((a["array_length"],a["array_local"],a["index_local"],a["source_cursor_local"],a["postincrement_old_cursor"],a["first_relative_input_byte"],a["last_relative_input_byte"])==(16,11,12,2,True,48,63),"original cursor and loop scope")
 need((struct.unpack_from("<i",body,0x36e)[0],0x372+struct.unpack_from("<i",body,0x36e)[0])==(18,0x384),"first original branch to guard")
 need((struct.unpack_from("<i",body,0x389)[0],0x38d+struct.unpack_from("<i",body,0x389)[0])==(-27,0x372),"signed blt original loop backedge")
 need((seg[1]["branch_displacement"],seg[1]["branch_target_il"])==(18,"0x0384") and (seg[4]["branch_displacement"],seg[4]["branch_target_il"])==(-27,"0x0372"),"witness branch targets")
 ty=a["array_type"];tok=int(ty["typeref_token"],16);rid=tok&0xffffff
 need(tok==0x010000D7 and rid<=rows[1],"original TypeRef token")
 rt=pe[o[1]+(rid-1)*z[1]:o[1]+rid*z[1]]
 width=z[1]-2*s;ni=struct.unpack_from("<I" if s==4 else "<H",rt,width)[0]
 ns=struct.unpack_from("<I" if s==4 else "<H",rt,width+s)[0]
 need(rt.hex()==ty["metadata_row_hex"] and (base.s_at(pe,sb,ni),base.s_at(pe,sb,ns))==(ty["name"],ty["namespace"])==("Int32","System"),"actual System.Int32 TypeRef")
 need(ty["element_store_opcode"]=="stelem.i4" and a["read_opcode"]=="ldelem.u1" and body[0x37c]==0x91 and body[0x37d]==0x9e,"original unsigned read/int32 store opcodes")
 call=a["target_method"];cm=base.method(pe,sections,s,b,ix,z,o,sb,bb,owners,int(call["methoddef_token"],16))
 need((call["methoddef_token"],cm[0],cm[4],cm[5],cm[7])==("0x06005265",call["row_hex"],call["name"],call["signature_hex"],(call["owner"],"")),"original GetAnmNum method row and signature")
 need(cm[5]=="0001081d08" and call["signature_reading"]=="static int32 GetAnmNum(int32[])","original static array signature")
 field=a["destination_field"];f=base.field(pe,s,b,z,o,sb,bb,fm,int(field["fielddef_token"],16))
 need((field["fielddef_token"],f)==("0x04007C54",(field["row_hex"],(field["owner"],""),field["name"],field["signature_hex"])),"original anmNum destination FieldDef")
 return {"source":"DLL-001","method_sha256":m["code_sha256"],"window_sha256":a["source_sha256"],"element_count":16,"source_offsets":[48,63],"array_element_type":"System.Int32","called_method":"SkillDataMan.GetAnmNum","destination":"SkillData.anmNum","gameplay_semantics":"OPEN"}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SIXTEEN_INT32_ANMNUM_SOURCE_LOOP_V1" and w["source_ids"]==["DLL-001"],"source manifest identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_SKILL_DATA_MAN_RSF_SIXTEEN_ANMNUM_SOURCE_LOOP: PASS")
  return 0
 except Exception as e:
  print("PROVE_SKILL_DATA_MAN_RSF_SIXTEEN_ANMNUM_SOURCE_LOOP: FAIL",str(e))
  return 1
if __name__=="__main__":raise SystemExit(main())
