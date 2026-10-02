#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003245E4
SIZE=411
CODE_SHA="190881f0b3580bf1117c3f937040340778b36c472ddd6d9db01ae15286fa458a"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def locate(ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:return rp+rva-va
 raise E("rva")
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def brs(c,o,op,target,l):
 if c[o]!=op or o+2+struct.unpack_from("<b",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);o=locate(ss,RVA);fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4
 if (fs&0x0FFF)!=0x0013 or h!=12 or struct.unpack_from("<H",pe,o+2)[0]!=4 or struct.unpack_from("<I",pe,o+8)[0]!=0x11000047:raise E("header")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 c=pe[o+h:o+h+SIZE]
 if hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 tok(c,0x0001,0x7B,0x0400C229,"$PC load")
 tok(c,0x0009,0x7D,0x0400C229,"$PC=-1")
 if c[0x000F]!=0x45 or struct.unpack_from("<I",c,0x0010)[0]!=3:raise E("switch")
 base=0x0020;tg=[base+struct.unpack_from("<i",c,0x0014+4*i)[0] for i in range(3)]
 if tg!=[0x0025,0x00CD,0x0135]:raise E("switch targets")
 br(c,0x0020,0x38,0x0197,"default")
 tok(c,0x0025,0x7E,0x04008700,"clip list")
 br(c,0x002A,0x39,0x0034,"clip list null")
 if c[0x0034]!=0x1F or struct.unpack_from("<b",c,0x0035)[0]!=48:raise E("AudioClip[48]")
 tok(c,0x0036,0x8D,0x01000012,"AudioClip[]")
 tok(c,0x003B,0x80,0x04008700,"clip list store")
 tok(c,0x0041,0x7E,0x0400866E,"AnnouncerVoiceDataNum")
 tok(c,0x0047,0x7B,0x0400C221,"type")
 tok(c,0x004D,0x8D,0x01000190,"ResourceRequest[]")
 tok(c,0x0052,0x7D,0x0400C222,"resReq store")
 tok(c,0x0064,0x7E,0x0400866F,"AnnouncerVoiceFilePrefix")
 tok(c,0x006A,0x7B,0x0400C221,"type prefix")
 tok(c,0x0070,0x72,0x700082AA,"format string")
 tok(c,0x0080,0x28,0x0A00050B,"String.Format")
 tok(c,0x0085,0x28,0x0A000012,"String.Concat")
 tok(c,0x008A,0x7D,0x0400C224,"fn store")
 tok(c,0x00A1,0x28,0x0A000675,"Resources.LoadAsync")
 tok(c,0x00A8,0x7B,0x0400C225,"background")
 br(c,0x00AD,0x39,0x00CD,"background false")
 tok(c,0x00B4,0x7D,0x0400C227,"current null")
 tok(c,0x00BA,0x7B,0x0400C228,"disposing #1")
 brs(c,0x00BF,0x2D,0x00C8,"disposing #1")
 tok(c,0x00C3,0x7D,0x0400C229,"PC=1")
 tok(c,0x0117,0x73,0x0A000679,"WaitForSeconds ctor")
 tok(c,0x011C,0x7D,0x0400C227,"current wait")
 tok(c,0x0122,0x7B,0x0400C228,"disposing #2")
 brs(c,0x0127,0x2D,0x0130,"disposing #2")
 tok(c,0x012B,0x7D,0x0400C229,"PC=2")
 tok(c,0x0142,0x6F,0x0A000676,"get_isDone")
 br(c,0x0147,0x39,0x0111,"not done")
 tok(c,0x0164,0x6F,0x0A000677,"get_asset")
 tok(c,0x0169,0x75,0x01000012,"AudioClip cast")
 if c[0x0190:0x0192]!=bytes([0x02,0x15]):raise E("final PC args")
 tok(c,0x0192,0x7D,0x0400C229,"final PC=-1")
 if c[0x0197:0x019B]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_LOAD_ASYNC_ANNOUNCER_VOICE_MOVENEXT: PASS")
if __name__=="__main__":main()
