#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
0x00321783:(bytes.fromhex("02280e00000a2a"),"6e817ef204d70afc9203c9b23a4ac0c48eef5f9317a62a9d916cb6e6875bffd6"),
0x00321792:(bytes.fromhex("0280ea8600042a"),"0151580d8e132f0a6a0dcb6f2286d921d85461fb76c79ddda417ea011c1c9d28"),
0x0032179C:(bytes.fromhex("7ef48600043a2b0000001f278d8a0a000280f4860004160a38100000007ef48600040673c1520006a20617580a061f273fe8ffffff1680fc8600040228805200062a"),"f132c681f5788ca9c7581ed581d24de4c4acd0f6c7edb55614cc6ab165b6cf32"),
0x003217EA:(bytes.fromhex("2a"),"684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"),
0x003217EC:(bytes.fromhex("287c52000614280600000a398c0000007286ea0870286206000a0a066f4a00002b261e8d8b0a000280eb860004160b38100000007eeb8600040773c3520006a20717580b071e3fe9ffffff160c38160000007eeb860004089a066f4c00002b7d4c8700040817580c081e3fe3ffffff1680f5860004066fe103002b287d52000606289b01000a1f278dce00000180ed86000428815200062883520006281c0a000a0d1203281d0a000a722e700070282f00000a3a1d000000281c0a000a13041204281d0a000a728e330470282f00000a39110000000272a2ea087028c400000a26380500000028835200062a"),"11a01435a5eb88584d4a811a33bda97f11287b086c17dbae432748e51e0e4d23"),
0x003237ED:(bytes.fromhex("0228ef00000a2a"),"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"),
0x003237FE:(bytes.fromhex("0228ef00000a2a"),"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9")
}
class E(RuntimeError):pass
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];opt=struct.unpack_from("<H",pe,q+20)[0];so=q+24+opt;out=[]
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def need(c,off,op,t,label):
 if c[off]!=op or struct.unpack_from("<I",c,off+1)[0]!=t:raise E(label)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=secs(pe); bodies={}
 for rva,(exp,sha) in M.items():
  c=body(pe,ss,rva);bodies[rva]=c
  if c!=exp or hashlib.sha256(c).hexdigest()!=sha:raise E(hex(rva))
 awake=bodies[0x0032179C]; init=bodies[0x003217EC]
 need(awake,0x0000,0x7E,0x040086F4,"audioClipInfo gate")
 if awake[0x000A:0x000C]!=bytes([0x1F,39]):raise E("AudioClipInfo count")
 need(awake,0x000C,0x8D,0x02000A8A,"AudioClipInfo newarr")
 need(awake,0x0023,0x73,0x060052C1,"AudioClipInfo ctor")
 need(awake,0x0036,0x80,0x040086FC,"load end false")
 need(awake,0x003C,0x28,0x06005280,"Initalize_State")
 need(init,0x0000,0x28,0x0600527C,"get_instance")
 need(init,0x0010,0x72,0x7008EA86,"Sound_Manager")
 need(init,0x0015,0x28,0x0A000662,"Find")
 need(init,0x001C,0x6F,0x2B00004A,"Add AudioListener")
 need(init,0x0023,0x8D,0x02000A8B,"AudioSrcInfo newarr")
 need(init,0x003A,0x73,0x060052C3,"AudioSrcInfo ctor")
 need(init,0x005A,0x6F,0x2B00004C,"Add AudioSource")
 need(init,0x005F,0x7D,0x0400874C,"sRefAudio store")
 need(init,0x0070,0x80,0x040086F5,"audio_source_index")
 need(init,0x0076,0x6F,0x2B0003E1,"GetComponent MenuSound")
 need(init,0x007B,0x28,0x0600527D,"set_instance")
 need(init,0x0081,0x28,0x0A00019B,"DontDestroy")
 if init[0x0086:0x0088]!=bytes([0x1F,39]):raise E("lockTimes count")
 need(init,0x0088,0x8D,0x010000CE,"Single newarr")
 need(init,0x008D,0x80,0x040086ED,"lockTimes")
 need(init,0x0092,0x28,0x06005281,"Resume_State")
 need(init,0x0097,0x28,0x06005283,"Load_SystemSe #1")
 need(init,0x00A9,0x72,0x7000702E,"Match")
 need(init,0x00C6,0x72,0x7004338E,"main")
 need(init,0x00D6,0x72,0x7008EAA2,"Load_MatchSe string")
 need(init,0x00DB,0x28,0x0A0000C4,"StartCoroutine String")
 need(init,0x00E6,0x28,0x06005283,"Load_SystemSe #2")
 print("PROVE_MENU_SOUND_INIT_SPINE: PASS")
if __name__=="__main__":main()
