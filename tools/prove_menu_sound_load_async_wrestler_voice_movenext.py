#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00323E44
SIZE=1521
CODE_SHA="4a24846ef6fe5b1e729ee484cbdac32e5744eb183a9b23562fd7d865a8410f94"
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
 if (fs&0x0FFF)!=0x0013 or h!=12 or struct.unpack_from("<H",pe,o+2)[0]!=5 or struct.unpack_from("<I",pe,o+8)[0]!=0x11001219:raise E("header")
 if struct.unpack_from("<I",pe,o+4)[0]!=SIZE:raise E("size")
 c=pe[o+h:o+h+SIZE]
 if hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 tok(c,0x0001,0x7B,0x0400C21A,"$PC load"); tok(c,0x0009,0x7D,0x0400C21A,"$PC=-1")
 if c[0x000F]!=0x45 or struct.unpack_from("<I",c,0x0010)[0]!=4:raise E("switch")
 base=0x0024;tg=[base+struct.unpack_from("<i",c,0x0014+4*i)[0] for i in range(4)]
 if tg!=[0x0029,0x032B,0x040C,0x04D2]:raise E("switch targets")
 br(c,0x0024,0x38,0x05ED,"default")
 tok(c,0x0030,0x6F,0x0A000FAD,"request count #1"); tok(c,0x0035,0x8D,0x0100020D,"AssetBundleCreateRequest[]")
 tok(c,0x0046,0x6F,0x0A000FAD,"request count #2"); tok(c,0x004B,0x8D,0x010000BF,"String[]")
 tok(c,0x005C,0x6F,0x0A000FAD,"request count #3"); tok(c,0x0061,0x8D,0x010000D7,"Int32[]")
 tok(c,0x006B,0x7E,0x040086FD,"clip grid gate"); tok(c,0x0077,0x73,0x0A000FA3,"AudioClip[,] ctor"); tok(c,0x007C,0x80,0x040086FD,"clip grid store")
 tok(c,0x009A,0x6F,0x0A000FAE,"request get_item #1")
 tok(c,0x00BA,0x7B,0x0400874F,"pl_idx low"); tok(c,0x00CB,0x7B,0x0400874F,"pl_idx high")
 tok(c,0x00E1,0x7B,0x04008750,"slot low"); tok(c,0x00F2,0x7B,0x04008750,"slot high")
 tok(c,0x0108,0x7B,0x04008751,"type low"); tok(c,0x0119,0x7B,0x04008751,"type high")
 tok(c,0x013B,0x6F,0x060011E7,"GetWrestlerVoiceInfo #1"); tok(c,0x014B,0x7B,0x04008752,"vidx low")
 tok(c,0x0196,0x28,0x0A000FA4,"clip grid Get")
 tok(c,0x01BF,0x6F,0x060011E4,"IsDLC"); tok(c,0x01CF,0x6F,0x060011E3,"CheckValidationDLC")
 tok(c,0x01E2,0x72,0x7008EABC,"dlc prefix"); tok(c,0x0214,0x28,0x0A0001BF,"DLC path concat")
 tok(c,0x022A,0x72,0x700006E9,"underscore DLC"); tok(c,0x022F,0x72,0x700082AA,"format DLC")
 tok(c,0x02A7,0x28,0x0A00002F,"duplicate path equality"); tok(c,0x02FF,0x28,0x0A000FAB,"LoadFromFileAsync")
 tok(c,0x0312,0x7D,0x0400C218,"current null #1"); tok(c,0x0321,0x7D,0x0400C21A,"PC=1")
 tok(c,0x0339,0x72,0x7008EAE2,"resource prefix"); tok(c,0x0392,0x72,0x700082AA,"format resource")
 tok(c,0x03D7,0x28,0x0A0006DA,"Resources.Load"); tok(c,0x03DC,0x74,0x01000012,"AudioClip cast"); tok(c,0x03E1,0x28,0x0A000FA5,"clip Set resource")
 tok(c,0x03F3,0x7D,0x0400C218,"current null #2"); tok(c,0x0402,0x7D,0x0400C21A,"PC=2")
 tok(c,0x0464,0x6F,0x060011E7,"GetWrestlerVoiceInfo #2")
 tok(c,0x04B4,0x73,0x0A000679,"WaitForSeconds"); tok(c,0x04B9,0x7D,0x0400C218,"current wait"); tok(c,0x04C8,0x7D,0x0400C21A,"PC=3")
 tok(c,0x04DF,0x6F,0x0A000676,"isDone"); tok(c,0x04F6,0x6F,0x0A000FAC,"get_assetBundle #1")
 tok(c,0x052B,0x28,0x0A00050B,"String.Format bundle asset"); tok(c,0x0530,0x28,0x0A00001B,"String.Concat bundle asset")
 tok(c,0x055E,0x6F,0x0A000FAC,"get_assetBundle #2"); tok(c,0x0564,0x6F,0x2B000100,"LoadAsset<AudioClip>"); tok(c,0x0569,0x28,0x0A000FA5,"clip Set bundle")
 tok(c,0x05AE,0x6F,0x0A000FAC,"get_assetBundle #3"); tok(c,0x05C6,0x6F,0x0A000FAC,"get_assetBundle #4"); tok(c,0x05CC,0x6F,0x0A00079E,"Unload(false)")
 tok(c,0x05E8,0x7D,0x0400C21A,"final PC=-1")
 if c[0x05ED:0x05F1]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_LOAD_ASYNC_WRESTLER_VOICE_MOVENEXT: PASS")
if __name__=="__main__":main()
