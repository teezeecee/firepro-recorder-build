#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
RVA=0x002E1AB0
TOKEN=0x06004EE0
METHOD_ROW_HEX="b01a2e0000008600a0250a009f490000553a"
SIGNATURE_HEX="20010108"
LOCAL_SIG_TOKEN=0x11001074
LOCAL_SIG_HEX="070112b508"
CODE_SIZE=91
CODE_SHA="f4436e9f21bb7d3b9eef160a5967c34e25eeaf52fcfcc87d41f6524ececa61eb"
PLAY_RVA=0x002DB718
PLAY_SIZE=364
PLAY_SHA="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"
WITNESS_SHA="ee0f5723f7ae37c9742c154b75dd9055dc2b04cf84e8c9b60b76f82801fde1bf"
WITNESS_BYTES=794

class E(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sha_stream(f):
    h=hashlib.sha256()
    for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]
    osz=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+osz
    out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out

def rvaoff(ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz: return rp+rva-va
    raise E("RVA unmapped "+hex(rva))

def method(pe,ss,rva):
    o=rvaoff(ss,rva)
    b=pe[o]
    if b&3==2:
        return {"offset":o,"header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
    if b&3!=3: raise E("bad method header")
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4
    n=struct.unpack_from("<I",pe,o+4)[0]
    return {"offset":o,"header":h,"flags":fs&0x0FFF,
            "max_stack":struct.unpack_from("<H",pe,o+2)[0],
            "local_sig":struct.unpack_from("<I",pe,o+8)[0],
            "code":pe[o+h:o+h+n]}

def tok(c,o,op,t,label):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise E(label)

def br(c,o,op,target,label):
    if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target: raise E(label)

def metadata(pe,ss):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    opt=struct.unpack_from("<H",pe,q+20)[0]
    oo=q+24
    magic=struct.unpack_from("<H",pe,oo)[0]
    dd=oo+(112 if magic==0x20b else 96)
    cli=rvaoff(ss,struct.unpack_from("<I",pe,dd+14*8)[0])
    mo=rvaoff(ss,struct.unpack_from("<I",pe,cli+8)[0])
    vl=struct.unpack_from("<I",pe,mo+12)[0]
    p=(mo+16+vl+3)&~3
    _,ns=struct.unpack_from("<HH",pe,p); p+=4
    streams={}
    for _ in range(ns):
        off,size=struct.unpack_from("<II",pe,p); p+=8
        e=pe.index(b"\0",p)
        name=pe[p:e].decode()
        p=(e+4)&~3
        streams[name]=(mo+off,size)
    t=streams["#~"][0]
    p=t+4
    _,_,hs,_=struct.unpack_from("<BBBB",pe,p); p+=4
    valid,_=struct.unpack_from("<QQ",pe,p); p+=16
    rows={}
    for tid in range(64):
        if (valid>>tid)&1:
            rows[tid]=struct.unpack_from("<I",pe,p)[0]; p+=4
    return streams,hs,rows,p

def blob(pe,base,ix):
    p=base+ix
    b=pe[p]
    if b<0x80: n=b; p+=1
    elif b<0xC0: n=((b&0x3f)<<8)|pe[p+1]; p+=2
    else: n=((b&0x1f)<<24)|(pe[p+1]<<16)|(pe[p+2]<<8)|pe[p+3]; p+=4
    return pe[p:p+n]

def verify_metadata(pe,ss):
    streams,hs,rows,p=metadata(pe,ss)
    strsz=4 if hs&1 else 2
    guidsz=4 if hs&2 else 2
    blobsz=4 if hs&4 else 2
    def ix(t): return 4 if rows.get(t,0)>=65536 else 2
    def cix(tables,bits): return 4 if max(rows.get(t,0) for t in tables)>=(1<<(16-bits)) else 2
    def rd(pos,n):
        return (struct.unpack_from("<I",pe,pos)[0] if n==4 else struct.unpack_from("<H",pe,pos)[0],pos+n)
    sizes={
      0:2+strsz+guidsz*3,
      1:cix([0,26,35,1],2)+strsz*2,
      2:4+strsz*2+cix([2,1,27],2)+ix(4)+ix(6),
      3:ix(4),
      4:2+strsz+blobsz,
      5:ix(6),
      6:4+2+2+strsz+blobsz+ix(8),
      7:ix(8),
      8:2+2+strsz,
      9:ix(2)+cix([2,1,27],2),
      10:cix([2,1,26,6,27],3)+strsz+blobsz,
      11:2+cix([4,8,23],2)+blobsz,
      12:cix([6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43],5)+cix([6,10],3)+blobsz,
      13:cix([4,8],1)+blobsz,
      14:2+cix([2,6,32],2)+blobsz,
      15:2+4+ix(2),
      16:4+ix(4),
      17:blobsz
    }
    offs={}
    cur=p
    for tid in range(18):
        if tid in rows:
            offs[tid]=cur
            cur+=sizes[tid]*rows[tid]
    rid=TOKEN&0xffffff
    row=pe[offs[6]+(rid-1)*sizes[6]:offs[6]+rid*sizes[6]]
    if row.hex()!=METHOD_ROW_HEX: raise E("MethodDef row")
    pos=offs[6]+(rid-1)*sizes[6]+8
    nix,pos=rd(pos,strsz); six,pos=rd(pos,blobsz); pix,pos=rd(pos,ix(8))
    sbase=streams["#Strings"][0]
    e=pe.index(b"\0",sbase+nix)
    if pe[sbase+nix:e].decode()!="EquipWeapon": raise E("method name")
    if blob(pe,streams["#Blob"][0],six).hex()!=SIGNATURE_HEX: raise E("signature blob")
    ppos=offs[8]+(pix-1)*sizes[8]
    _,seq=struct.unpack_from("<HH",pe,ppos); ppos+=4
    pnix,_=rd(ppos,strsz)
    pe_end=pe.index(b"\0",sbase+pnix)
    if seq!=1 or pe[sbase+pnix:pe_end].decode()!="widx": raise E("parameter metadata")
    srid=LOCAL_SIG_TOKEN&0xffffff
    spos=offs[17]+(srid-1)*sizes[17]
    six,_=rd(spos,blobsz)
    if blob(pe,streams["#Blob"][0],six).hex()!=LOCAL_SIG_HEX: raise E("local signature blob")

def verify_dll(path):
    pe=Path(path).read_bytes()
    got=hashlib.sha256(pe).hexdigest()
    if got!=DLL_SHA: raise E("DLL SHA "+got)
    ss=sections(pe)
    verify_metadata(pe,ss)
    m=method(pe,ss,RVA); c=m["code"]
    if len(c)!=CODE_SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise E("EquipWeapon body")
    if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=LOCAL_SIG_TOKEN: raise E("EquipWeapon header")
    if c[0]!=0x02: raise E("this #1")
    tok(c,0x0001,0x7B,0x0400600B,"Player.weaponIdx read")
    if c[0x0006]!=0x16: raise E("raw zero")
    br(c,0x0007,0x3F,0x000D,"signed weaponIdx < 0")
    if c[0x000C]!=0x2A: raise E("already armed return")
    tok(c,0x000D,0x7E,0x0400B6EA,"WeaponMan.inst")
    if c[0x0012]!=0x03: raise E("widx load")
    tok(c,0x0013,0x6F,0x06006AC8,"WeaponMan.GetWeaponObj")
    if c[0x0018:0x001A]!=bytes([0x0A,0x06]): raise E("Weapon local")
    tok(c,0x001A,0x28,0x0A00002A,"Unity Object op_Implicit")
    br(c,0x001F,0x3A,0x0025,"Weapon non-null")
    if c[0x0024]!=0x2A: raise E("null return")
    if c[0x0025:0x0027]!=bytes([0x02,0x03]): raise E("this/widx store args")
    tok(c,0x0027,0x7D,0x0400600B,"Player.weaponIdx write")
    if c[0x002C:0x002E]!=bytes([0x06,0x17]): raise E("Weapon/raw1")
    tok(c,0x002E,0x7D,0x0400B6D5,"Weapon.State write")
    if c[0x0033:0x0035]!=bytes([0x06,0x02]): raise E("Weapon/Player")
    tok(c,0x0035,0x7B,0x04005FA6,"Player.PlIdx")
    tok(c,0x003A,0x7D,0x0400B6DC,"Weapon.PlIdx write")
    if c[0x003F]!=0x06: raise E("Weapon transform base")
    tok(c,0x0040,0x6F,0x0A000028,"Weapon get_gameObject")
    tok(c,0x0045,0x6F,0x0A000050,"Weapon get_transform")
    if c[0x004A]!=0x02: raise E("Player transform base")
    tok(c,0x004B,0x28,0x0A000028,"Player get_gameObject")
    tok(c,0x0050,0x6F,0x0A000050,"Player get_transform")
    tok(c,0x0055,0x6F,0x0A0007A2,"Transform.SetParent")
    if c[0x005A]!=0x2A: raise E("ret")
    p=method(pe,ss,PLAY_RVA)["code"]
    if len(p)!=PLAY_SIZE or hashlib.sha256(p).hexdigest()!=PLAY_SHA: raise E("FACT-0015 caller body")
    tok(p,0x00E9,0x6F,TOKEN,"FACT-0015 EquipWeapon call")
    needle=bytes([0x6F])+struct.pack("<I",TOKEN)
    if p.count(needle)!=1: raise E("FACT-0015 EquipWeapon callsite count")
    return {"dll_sha256":got,"code_size":len(c),"code_sha256":CODE_SHA}

def verify_r6(path):
    got=sha_path(path)
    if got!=R6_SHA: raise E("R6 SHA "+got)
    with zipfile.ZipFile(path) as z:
        bad=z.testzip()
        if bad: raise E("ZIP CRC "+bad)
        names=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        if len(names)!=1: raise E("event_trace count")
        name=names[0]
        with z.open(name) as f:
            esha=sha_stream(f)
        if esha!=EVENT_SHA: raise E("event SHA "+esha)
        stack=[]; equips=[]
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                ph=row["phase"]
                if ph=="MARK": continue
                if ph=="PRE":
                    parent=stack[-1] if stack else None
                    node={"line":line,"row":dict(row),"parent":parent,"post":None,"post_line":None,"children":[]}
                    if parent: parent["children"].append(node)
                    stack.append(node)
                elif ph=="POST":
                    if not stack: raise E("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]: raise E("non-LIFO trace")
                    node["post"]=dict(row); node["post_line"]=line
                    if node["row"]["method"]=="Player.EquipWeapon": equips.append(node)
        if stack: raise E("unterminated trace")
    if len(equips)!=11: raise E("EquipWeapon count "+str(len(equips)))
    argcounts=Counter(); rel=Counter(); records=[]
    fields=("parent_pre_line","parent_post_line","equip_pre_line","equip_post_line","tick","seq","owner_slot","instance","arg","parent_pre_weaponIdx","parent_post_weaponIdx","equip_pre_weaponIdx","equip_post_weaponIdx")
    for n in equips:
        p=n["parent"]
        if not p or p["row"]["method"]!="FormAnimator.PlayAnimationSE": raise E("EquipWeapon direct parent")
        if p["post"] is None: raise E("parent POST missing")
        rel["parent_PRE_weaponIdx_minus1"]+=p["row"]["weaponIdx"]=="-1"
        rel["equip_PRE_weaponIdx_minus1"]+=n["row"]["weaponIdx"]=="-1"
        rel["equip_owner_slot_equals_parent_owner_slot"]+=n["row"]["owner_slot"]==p["row"]["owner_slot"]
        rel["equip_raw_arg_equals_equip_POST_weaponIdx"]+=n["row"]["args"]==n["post"]["weaponIdx"]
        rel["parent_POST_weaponIdx_equals_equip_raw_arg"]+=p["post"]["weaponIdx"]==n["row"]["args"]
        argcounts[n["row"]["args"]]+=1
        records.append({
          "parent_pre_line":p["line"],"parent_post_line":p["post_line"],
          "equip_pre_line":n["line"],"equip_post_line":n["post_line"],
          "tick":n["row"]["tick"],"seq":n["row"]["seq"],
          "owner_slot":n["row"]["owner_slot"],"instance":n["row"]["instance"],"arg":n["row"]["args"],
          "parent_pre_weaponIdx":p["row"]["weaponIdx"],"parent_post_weaponIdx":p["post"]["weaponIdx"],
          "equip_pre_weaponIdx":n["row"]["weaponIdx"],"equip_post_weaponIdx":n["post"]["weaponIdx"]
        })
    for k in ("parent_PRE_weaponIdx_minus1","equip_PRE_weaponIdx_minus1","equip_owner_slot_equals_parent_owner_slot","equip_raw_arg_equals_equip_POST_weaponIdx","parent_POST_weaponIdx_equals_equip_raw_arg"):
        if rel[k]!=11: raise E(k+" "+str(rel[k]))
    if argcounts!=Counter({"3":3,"7":2,"5":2,"2":2,"0":1,"6":1}): raise E("argument counts "+repr(argcounts))
    witness="".join("\t".join(str(r[f]) for f in fields)+"\n" for r in records).encode("utf-8")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=WITNESS_BYTES or wsha!=WITNESS_SHA: raise E("witness digest "+str((len(witness),wsha)))
    return {"r6_sha256":got,"event_trace_sha256":esha,"record_count":len(records),"argument_counts":dict(sorted(argcounts.items())),"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dll",required=True)
    ap.add_argument("--r6",required=True)
    ap.add_argument("--out")
    a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True))
        print("PROVE_PLAYER_EQUIP_WEAPON: PASS")
        return 0
    except (OSError,ValueError,KeyError,IndexError,zipfile.BadZipFile,E) as e:
        print("PROVE_PLAYER_EQUIP_WEAPON: FAIL")
        print(str(e))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
