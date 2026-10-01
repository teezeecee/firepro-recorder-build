#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002A96A8
SIZE=390
CODE_SHA="ce8a2a91a564c9f28928b39c7d444dfe0758d3b771b7a142125e5bac4daaa2b5"
class E(RuntimeError): pass
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\\0\\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+z; out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out
def method(pe,ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz:
            o=rp+rva-va; break
    else: raise E("rva")
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
    return {"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,label):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise E(label)
def main():
    a=argparse.ArgumentParser(); a.add_argument("--dll",required=True); x=a.parse_args()
    pe=Path(x.dll).read_bytes()
    if hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("dll")
    m=method(pe,sections(pe),RVA); c=m["code"]
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise E("body")
    if m["flags"]!=0x0013 or m["max_stack"]!=3 or m["local_sig"]!=0x11000F48: raise E("header")
    tok(c,0x0001,0x7B,0x0400574F,"bgmReqTimer #1")
    tok(c,0x000F,0x7B,0x0400574F,"bgmReqTimer #2")
    tok(c,0x0016,0x7D,0x0400574F,"bgmReqTimer store")
    tok(c,0x0028,0x7E,0x04002AD1,"GlobalWork.inst")
    tok(c,0x002D,0x7B,0x04002AD2,"MatchSetting")
    tok(c,0x0036,0x7B,0x040057D3,"BattleRoyalKind")
    tok(c,0x0040,0x7E,0x040056FF,"MatchEvaluation.inst #1")
    tok(c,0x0045,0x7B,0x04005700,"PlResult #1")
    tok(c,0x004C,0x7B,0x040056CF,"resultPosition #1")
    tok(c,0x0058,0x7B,0x040057EF,"suppress blue")
    tok(c,0x0062,0x7E,0x040056FF,"MatchEvaluation.inst #2")
    tok(c,0x0067,0x7B,0x04005700,"PlResult #2")
    tok(c,0x006E,0x7B,0x040056CF,"resultPosition #2")
    tok(c,0x007A,0x7B,0x040057F0,"suppress red")
    tok(c,0x008A,0x7D,0x04005743,"exitTimer=900")
    tok(c,0x0095,0x7B,0x04005743,"exitTimer eligibility #1")
    tok(c,0x00A5,0x7B,0x040057CF,"GameSpeed #1")
    tok(c,0x00B9,0x7B,0x04005743,"exitTimer eligibility #2")
    tok(c,0x00C9,0x7B,0x040057CF,"GameSpeed #2")
    tok(c,0x00DE,0x7B,0x0400574D,"ThemeMusic minus1")
    tok(c,0x00E9,0x72,0x7005B2B2,"BGIN_001")
    tok(c,0x00F0,0x28,0x06005298,"Change_BGM_Theme string")
    tok(c,0x00FB,0x7B,0x0400574D,"ThemeMusic minus2")
    tok(c,0x0108,0x7B,0x0400574E,"ThemeMusicFilename check")
    tok(c,0x010D,0x28,0x06002C1E,"FACT-0100 Check_File")
    tok(c,0x011A,0x28,0x06005296,"FACT-0111 Change_BGM_Theme false")
    tok(c,0x0121,0x7E,0x0A000025,"String.Empty #1")
    tok(c,0x0126,0x28,0x06002C23,"FACT-0110 MyMusic.Set false")
    tok(c,0x0130,0x28,0x060052A4,"StopBGM")
    tok(c,0x0138,0x7B,0x0400574E,"ThemeMusicFilename set")
    tok(c,0x013D,0x28,0x06002C23,"FACT-0110 MyMusic.Set true")
    tok(c,0x0145,0x28,0x0600529E,"Play_BGM")
    tok(c,0x0150,0x7B,0x0400574D,"ThemeMusic threshold #1")
    tok(c,0x0160,0x7B,0x0400574D,"ThemeMusic threshold #2")
    tok(c,0x0167,0x28,0x06005296,"FACT-0111 Change_BGM_Theme direct")
    tok(c,0x0174,0x28,0x06005296,"FACT-0111 Change_BGM_Theme fallback")
    tok(c,0x017B,0x7E,0x0A000025,"String.Empty #2")
    tok(c,0x0180,0x28,0x06002C23,"FACT-0110 MyMusic.Set fallback")
    if c[0x0185]!=0x2A: raise E("ret")
    print("PROVE_MATCH_MAIN_PLAY_AFTER_MATCH_BGM: PASS")
if __name__=="__main__": main()
