#!/usr/bin/env python3
import argparse, hashlib, json, struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
DLL_SIZE=8171008
TARGET=0x06006AC8
TARGET_RVA=0x00435402
TARGET_ROW="02544300000086006bcf0a00b1370300ac4d"
TARGET_SIG="200112b50808"
TARGET_CODE_SIZE=25
TARGET_CODE_SHA="e14e6ddd19807cae5dc1385638f47047f66403daae447e5cdaaa53a82253a0ee"
TARGET_BODY=bytes.fromhex("03163f07000000031e3f02000000142a027becb60004039a2a")
FIELD=0x0400B6EC
FIELD_SIG="061d12b508"
CALLERS=[
("FormRenderer","ApplySortingOrder",0x06001F4F,0x0010D064,386,"7d8231de8b396ae2209938f3104bd31a271a1009ceb600276f47492872f47066",0x0097,0x6F),
("FormRenderer","SetWeaponObj",0x06001F54,0x0010D600,529,"9a90ee6e931c2e7e58f746ae75c41d44998fb63a7da7dac8972b34f1d2284ecf",0x0020,0x6F),
("FormAnimator","ReqSlotAnm",0x06004E70,0x002D9FB8,722,"c4c109776883423823725f70612e1a7cd7e61367d7680c206bcc838470cf88ef",0x00FD,0x6F),
("Player","ThrowInWeapon",0x06004EDE,0x002E19DC,90,"60ce1799839692db53c9e180e8d10054a41a1882652de715101d2c79707db0ab",0x0018,0x6F),
("Player","EquipWeapon",0x06004EE0,0x002E1AB0,91,"f4436e9f21bb7d3b9eef160a5967c34e25eeaf52fcfcc87d41f6524ececa61eb",0x0013,0x6F),
("Player","ProcessAttackHit_Normal",0x06004F2A,0x002E9D80,1272,"9b0ee15ab9d50d7c55f283494967415fb4b3ab70e096088cafdafba068efe313",0x007D,0x6F),
("PlayerController_AI","AIActFunc_StandAtk",0x06004FC5,0x002F7DE8,800,"f6de274e9ab27bd900abddb1d8585e70fc69f0d02b52a0a8317e21e0c87231b4",0x003E,0x6F),
("PlayerController_AI","vpc_getkyo1",0x06004FCE,0x002F8A34,112,"5c3ee57e9c69cff9e8f29e9c67974c4286545b9028ca2cbc25a681e406f1a4b3",0x000B,0x6F),
("WeaponMan","Drop",0x06006AC9,0x0043541C,33,"edcc7cf0273d8a9e58e2e252323436fb039630779892b4c0e2e9654eddab7f76",0x0002,0x28),
]

class E(RuntimeError): pass

def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]
    z=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+z
    out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out,q

def rvaoff(ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz: return rp+rva-va
    raise E("RVA "+hex(rva))

def method(pe,ss,rva):
    o=rvaoff(ss,rva)
    b=pe[o]
    if b&3==2:
        n=b>>2
        return {"format":"tiny","header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+n]}
    if b&3!=3: raise E("method header")
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4
    n=struct.unpack_from("<I",pe,o+4)[0]
    return {"format":"fat","header":h,"flags":fs&0xfff,"max_stack":struct.unpack_from("<H",pe,o+2)[0],
            "local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}

def metadata(pe,ss,q):
    oo=q+24
    magic=struct.unpack_from("<H",pe,oo)[0]
    dd=oo+(112 if magic==0x20b else 96)
    cli=rvaoff(ss,struct.unpack_from("<I",pe,dd+14*8)[0])
    md=rvaoff(ss,struct.unpack_from("<I",pe,cli+8)[0])
    if pe[md:md+4]!=b"BSJB": raise E("CLI metadata")
    vl=struct.unpack_from("<I",pe,md+12)[0]
    p=(md+16+vl+3)&~3
    _,ns=struct.unpack_from("<HH",pe,p); p+=4
    streams={}
    for _ in range(ns):
        off,size=struct.unpack_from("<II",pe,p); p+=8
        e=pe.index(b"\0",p); name=pe[p:e].decode(); p=(e+4)&~3
        streams[name]=(md+off,size)
    t=streams["#~"][0]
    p=t+4
    _,_,hs,_=struct.unpack_from("<BBBB",pe,p); p+=4
    valid,_=struct.unpack_from("<QQ",pe,p); p+=16
    rows={}
    for tid in range(64):
        if (valid>>tid)&1:
            rows[tid]=struct.unpack_from("<I",pe,p)[0]; p+=4
    return streams,hs,rows,p

def setup_tables(pe,streams,hs,rows,p):
    strsz=4 if hs&1 else 2; guidsz=4 if hs&2 else 2; blobsz=4 if hs&4 else 2
    def ix(t): return 4 if rows.get(t,0)>=65536 else 2
    def cix(ts,bits): return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-bits)) else 2
    sizes={
      0:2+strsz+guidsz*3,
      1:cix([0,26,35,1],2)+strsz*2,
      2:4+strsz*2+cix([2,1,27],2)+ix(4)+ix(6),
      3:ix(4),4:2+strsz+blobsz,5:ix(6),
      6:4+2+2+strsz+blobsz+ix(8),7:ix(8),8:2+2+strsz,
      9:ix(2)+cix([2,1,27],2),10:cix([2,1,26,6,27],3)+strsz+blobsz,
      11:2+cix([4,8,23],2)+blobsz,
      12:cix([6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43],5)+cix([6,10],3)+blobsz,
      13:cix([4,8],1)+blobsz,14:2+cix([2,6,32],2)+blobsz,
      15:2+4+ix(2),16:4+ix(4),17:blobsz
    }
    offs={}; cur=p
    for tid in range(18):
        if tid in rows:
            if tid not in sizes: raise E("table size "+str(tid))
            offs[tid]=cur; cur+=sizes[tid]*rows[tid]
    return strsz,blobsz,ix,cix,sizes,offs

def rd(pe,pos,n):
    return ((struct.unpack_from("<I",pe,pos)[0],pos+4) if n==4 else (struct.unpack_from("<H",pe,pos)[0],pos+2))

def blob(pe,base,ixv):
    p=base+ixv; b=pe[p]
    if b<0x80: n=b; p+=1
    elif b<0xC0: n=((b&0x3f)<<8)|pe[p+1]; p+=2
    else: n=((b&0x1f)<<24)|(pe[p+1]<<16)|(pe[p+2]<<8)|pe[p+3]; p+=4
    return pe[p:p+n]

def verify_metadata(pe,streams,hs,rows,p):
    strsz,blobsz,ix,cix,sizes,offs=setup_tables(pe,streams,hs,rows,p)
    sb=streams["#Strings"][0]; bb=streams["#Blob"][0]
    def string(i):
        e=pe.index(b"\0",sb+i); return pe[sb+i:e].decode()
    rid=TARGET&0xffffff
    o=offs[6]+(rid-1)*sizes[6]
    row=pe[o:o+sizes[6]]
    if row.hex()!=TARGET_ROW: raise E("MethodDef row")
    rva,implf,flags=struct.unpack_from("<IHH",pe,o)
    pos=o+8; ni,pos=rd(pe,pos,strsz); si,pos=rd(pe,pos,blobsz); pi,pos=rd(pe,pos,ix(8))
    if rva!=TARGET_RVA or string(ni)!="GetWeaponObj" or blob(pe,bb,si).hex()!=TARGET_SIG: raise E("method metadata")
    # owner TypeDef is RID 3396; prove name and method range
    to=offs[2]+(3396-1)*sizes[2]; pos=to+4
    tni,pos=rd(pe,pos,strsz); nsi,pos=rd(pe,pos,strsz); _,pos=rd(pe,pos,cix([2,1,27],2)); _,pos=rd(pe,pos,ix(4)); ml,pos=rd(pe,pos,ix(6))
    nto=offs[2]+3396*sizes[2]; npos=nto+4
    _,npos=rd(pe,npos,strsz); _,npos=rd(pe,npos,strsz); _,npos=rd(pe,npos,cix([2,1,27],2)); _,npos=rd(pe,npos,ix(4)); nml,npos=rd(pe,npos,ix(6))
    if string(tni)!="WeaponMan" or not (ml<=rid<nml): raise E("method owner")
    po=offs[8]+(pi-1)*sizes[8]
    _,seq=struct.unpack_from("<HH",pe,po); ppos=po+4; pni,_=rd(pe,ppos,strsz)
    if seq!=1 or string(pni)!="idx": raise E("parameter metadata")
    frid=FIELD&0xffffff
    fo=offs[4]+(frid-1)*sizes[4]; fpos=fo+2
    fni,fpos=rd(pe,fpos,strsz); fsi,fpos=rd(pe,fpos,blobsz)
    if string(fni)!="WeaponObj" or blob(pe,bb,fsi).hex()!=FIELD_SIG: raise E("field metadata")
    return sizes,offs

def verify_target(pe,ss):
    m=method(pe,ss,TARGET_RVA); c=m["code"]
    if m["format"]!="tiny" or len(c)!=TARGET_CODE_SIZE or hashlib.sha256(c).hexdigest()!=TARGET_CODE_SHA or c!=TARGET_BODY:
        raise E("target body")
    # exact emitted flow and operands
    if c[0:2]!=bytes([0x03,0x16]): raise E("idx/raw0")
    if c[2]!=0x3F or 2+5+struct.unpack_from("<i",c,3)[0]!=0x000E: raise E("signed idx<0")
    if c[7:9]!=bytes([0x03,0x1E]): raise E("idx/raw8")
    if c[9]!=0x3F or 9+5+struct.unpack_from("<i",c,10)[0]!=0x0010: raise E("signed idx<8")
    if c[14:16]!=bytes([0x14,0x2A]): raise E("null return")
    if c[16]!=0x02 or c[17]!=0x7B or struct.unpack_from("<I",c,18)[0]!=FIELD: raise E("WeaponObj field")
    if c[22:25]!=bytes([0x03,0x9A,0x2A]): raise E("idx/ldelem.ref/ret")

def parse_method_row(pe,streams,hs,rows,p,mrid,method_owner):
    strsz,blobsz,ix,cix,sizes,offs=setup_tables(pe,streams,hs,rows,p)
    sb=streams["#Strings"][0]; bb=streams["#Blob"][0]
    def string(i):
        e=pe.index(b"\0",sb+i); return pe[sb+i:e].decode()
    o=offs[6]+(mrid-1)*sizes[6]
    rva,implf,flags=struct.unpack_from("<IHH",pe,o); pos=o+8
    ni,pos=rd(pe,pos,strsz); si,pos=rd(pe,pos,blobsz); pl,pos=rd(pe,pos,ix(8))
    return {"rva":rva,"name":string(ni),"sig":blob(pe,bb,si).hex(),"type":method_owner[mrid]}

def build_method_owner(pe,streams,hs,rows,p):
    strsz,blobsz,ix,cix,sizes,offs=setup_tables(pe,streams,hs,rows,p)
    sb=streams["#Strings"][0]
    def string(i):
        e=pe.index(b"\0",sb+i); return pe[sb+i:e].decode()
    typedefs=[]
    for trid in range(1,rows[2]+1):
        o=offs[2]+(trid-1)*sizes[2]; pos=o+4
        ni,pos=rd(pe,pos,strsz); nsi,pos=rd(pe,pos,strsz); _,pos=rd(pe,pos,cix([2,1,27],2)); _,pos=rd(pe,pos,ix(4)); ml,pos=rd(pe,pos,ix(6))
        ns=string(nsi); name=string(ni); typedefs.append((ml,(ns+"."+name if ns else name)))
    owner={}
    for i,(start,name) in enumerate(typedefs):
        end=typedefs[i+1][0] if i+1<len(typedefs) else rows[6]+1
        for mrid in range(start,end): owner[mrid]=name
    return owner

def verify_callers(pe,ss,streams,hs,rows,p):
    owner=build_method_owner(pe,streams,hs,rows,p)
    expected={(t,n,tok,rva,sz,sha,il,op) for t,n,tok,rva,sz,sha,il,op in CALLERS}
    actual=[]
    needle=struct.pack("<I",TARGET)
    for mrid in range(1,rows[6]+1):
        md=parse_method_row(pe,streams,hs,rows,p,mrid,owner)
        if not md["rva"]: continue
        try: code=method(pe,ss,md["rva"])["code"]
        except Exception: continue
        for i in range(len(code)-4):
            if code[i] in (0x28,0x6F) and code[i+1:i+5]==needle:
                actual.append((md["type"],md["name"],0x06000000|mrid,md["rva"],len(code),hashlib.sha256(code).hexdigest(),i,code[i]))
    if set(actual)!=expected or len(actual)!=len(CALLERS): raise E("caller map "+repr(actual))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); a=ap.parse_args()
    pe=Path(a.dll).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("DLL identity")
    ss,q=sections(pe)
    streams,hs,rows,p=metadata(pe,ss,q)
    verify_metadata(pe,streams,hs,rows,p)
    verify_target(pe,ss)
    verify_callers(pe,ss,streams,hs,rows,p)
    print(json.dumps({"dll_sha256":DLL_SHA,"method_token":"0x06006AC8","code_size":TARGET_CODE_SIZE,
                      "code_sha256":TARGET_CODE_SHA,"direct_in_assembly_reference_count":len(CALLERS)},indent=2))
    print("PROVE_WEAPONMAN_GET_WEAPON_OBJ: PASS")

if __name__=="__main__":
    main()
