#!/usr/bin/env python3
"""FACT-0292: compare the complete original DLL FieldRVA 120x2 table and .cctor IL."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/anm_bank_data_file_num_tbl_source_120_pairs.summary.json"
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
CTOR_SHA="fbb695a6ddc0ccb80cf02a59b0d1761abec6590b352227e72fef7665be148393"
DATA_SHA="107e6a82ea8141420999dbb5c61ed597cdcb4d9cc74c941b1153ec5bd5ed215b"
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def memberref(pe,s,b,z,o,sb,bb,t):
 at=o[10]+((t&0xffffff)-1)*z[10];raw=pe[at:at+z[10]]
 code,at=base.rd(pe,at,z[10]-s-b);ni,at=base.rd(pe,at,s);sig,at=base.rd(pe,at,b)
 return raw.hex(),code,base.s_at(pe,sb,ni),base.blob(pe,bb,sig).hex()
def verify(path,w):
 pe=Path(path).read_bytes();d=w["dll"];ctor=d["static_constructor"]
 need((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"])==(8171008,DLL_SHA),"matching original DLL hash and size")
 ss,q=base.secs(pe);st,hs,rows,pos=base.mdstreams(pe,ss,q)
 s,b,ix,z,o=base.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
 fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
 md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005246);body=md[9]
 need((md[0],md[1],md[4],md[5],md[7])==(ctor["row_hex"],int(ctor["rva"],16),ctor["name"],ctor["signature_hex"],(ctor["owner"],"")),"original .cctor row, signature and owner")
 need(pe[base.off(ss,md[1]):md[8]].hex()==ctor["header_hex"]=="66","original tiny method header")
 need((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(25,ctor["il_hex"],CTOR_SHA)==(ctor["code_bytes"],ctor["il_hex"],ctor["code_sha256"]),"complete original static initialization IL")
 need((ctor["array_dimensions"],body[:3].hex())==([120,2],"1f7818"),"exact source array dimensions")
 sf=d["source_array_field"];df=d["destination_field"]
 for t,x in [(0x0400B8F6,sf),(0x0400656D,df)]:
  need(x["token"]==f"0x{t:08X}","original witness FieldDef")
  need(base.field(pe,s,b,z,o,sb,bb,fm,t)==(x["row_hex"],(x["owner"],""),x["name"],x["signature_hex"]),"original raw FieldDef "+x["token"])
 need((body[9:14],body[19:24])==(b"\xd0"+struct.pack("<I",0x0400B8F6),b"\x80"+struct.pack("<I",0x0400656D)),"source ldtoken and stsfld original fields")
 need((sf["ldtoken_il"],df["stsfld_il"])==("0x0009","0x0013"),"original field instruction offsets")
 need(len(d["calls"])==2,"original initialization method calls")
 for a,t,op,at in [(d["calls"][0],0x0A000713,0x73,3),(d["calls"][1],0x0A0001E5,0x28,14)]:
  need(a["token"]==f"0x{t:08X}","original MemberRef token")
  need(memberref(pe,s,b,z,o,sb,bb,t)==(a["row_hex"],int(a["class_coded"],16),a["name"],a["signature_hex"]),"original MemberRef raw metadata")
  need(body[at:at+5]==bytes([op])+struct.pack("<I",t),"original MemberRef source call")
 # ECMA-335 table layouts 18 to 29, extending the repository's metadata parser through FieldRVA.
 def coded(ts,tag_bits):return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-tag_bits)) else 2
 sizes={18:ix(2)+ix(20),19:ix(20),20:2+s+coded([2,1,27],2),21:ix(2)+ix(23),22:ix(23),23:2+s+b,24:2+ix(6)+coded([20,23],1),25:ix(2)+2*coded([6,10],1),26:s,27:b,28:2+coded([4,6],1)+s+ix(26),29:4+ix(4)}
 offset29=o[17]+rows[17]*z[17]+sum(rows.get(t,0)*sizes[t] for t in range(18,29))
 fr=d["field_rva"];rowstart=offset29+(fr["row_index_1_based"]-1)*sizes[29]
 need((rows[29],offset29,rowstart)==(fr["total_table_rows"],int(fr["table_file_offset"],16),int(fr["row_file_offset"],16))==(570,0x5f55a0,0x5f617c),"original FieldRVA row index and offset")
 row=pe[rowstart:rowstart+sizes[29]];need(row.hex()==fr["row_hex"]=="c0327b00f6b8","source FieldRVA raw entry")
 rva=struct.unpack_from("<I",row)[0];fid=struct.unpack_from("<H" if ix(4)==2 else "<I",row,4)[0]
 need((rva,fid)==(int(fr["rva"],16),0xB8F6),"FieldRVA source pointer")
 dataat=base.off(ss,rva);need(dataat==int(fr["file_offset"],16)==0x7afec0,"source RVA to PE offset")
 raw=pe[dataat:dataat+960]
 need((len(raw),hashlib.sha256(raw).hexdigest())==(fr["source_bytes"],fr["source_sha256"])==(960,DATA_SHA),"original entire 960 bytes SHA")
 vals=struct.unpack("<240i",raw);pairs=[[vals[i],vals[i+1]] for i in range(0,240,2)]
 need(pairs==d["bank_file_pairs"] and len(pairs)==d["pair_count"]==120,"exact 120 ordered source pairs")
 need(len({p[0] for p in pairs})==d["distinct_bank_ids"]==120,"source bank ID uniqueness")
 counts={str(k):v for k,v in collections.Counter(p[1] for p in pairs).items()}
 need(counts==d["file_count_histogram"]=={"1":78,"2":28,"3":14},"source bank count histogram")
 # The source newobj TypeSpec is a rank-2 int32 array.
 ts=d["array_type_spec"];rid=ts["rid"];p27=o[17]+rows[17]*z[17]+sum(rows.get(t,0)*sizes[t] for t in range(18,27))
 tsrow=pe[p27+(rid-1)*sizes[27]:p27+rid*sizes[27]]
 need(tsrow.hex()==ts["row_hex"] and base.blob(pe,bb,struct.unpack_from("<I" if b==4 else "<H",tsrow)[0]).hex()==ts["signature_hex"]=="14080200020000","original int32 rank-2 TypeSpec")
 ref=d["caller"];caller=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005244)
 need((ref["methoddef"],ref["reads_field"],hashlib.sha256(caller[9]).hexdigest())==("0x06005244","0x0400656D",ref["code_sha256"]),"linked original FileNumTbl consumer")
 return {"fact_id":"FACT-0292","original_DLL_SHA256":DLL_SHA,"static_ctor_sha256":CTOR_SHA,"source_data_sha256":DATA_SHA,"pairs":len(pairs),"counts":counts,"asset_resource_binding":"OPEN"}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
 try:
  w=json.loads(W.read_text(encoding="utf-8"))
  need(w["dataset_id"]=="DLL_ANM_BANK_DATA_FILE_NUM_TBL_SOURCE_120_PAIRS_V1" and w["source_ids"]==["DLL-001"],"witness identity")
  print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
  print("PROVE_ANM_BANK_DATA_FILE_NUM_TBL_SOURCE_120_PAIRS: PASS")
  return 0
 except Exception as exc:
  print("PROVE_ANM_BANK_DATA_FILE_NUM_TBL_SOURCE_120_PAIRS: FAIL",str(exc))
  return 1
if __name__=="__main__":raise SystemExit(main())
