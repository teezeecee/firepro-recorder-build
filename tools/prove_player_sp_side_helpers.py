#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
M={'ConsumeSP':(0x002E15D4,51,'0319a9b9582c72089b9455369fa000ad2d7713ad775bcb2eb0836f21c773d243'),'RecoverSP':(0x002E1614,100,'9879da28f6a20f4435ae4bb27ba85d7f920ce913279bdfd0a7df12ecfc797ddf'),'InvokeUkeBonus':(0x002E1684,144,'70c0105528475fabfc6a645f2b42355b7a3063334b6ee9abe25c09f00fa6e334')}
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from('<I',pe,0x3c)[0]
 if pe[q:q+4]!=b'PE\0\0':raise ProofError('not PE')
 n=struct.unpack_from('<H',pe,q+6)[0];osz=struct.unpack_from('<H',pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8);out.append((va,vs,rp,rs))
 return out
def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs):return rp+rva-va
 raise ProofError('RVA unmapped')
def mcode(pe,ss,rva):
 o=rvaoff(pe,ss,rva);b=pe[o]
 if b&3==2:h=1;n=b>>2
 elif b&3==3:
  fs=struct.unpack_from('<H',pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from('<I',pe,o+4)[0]
 else:raise ProofError('bad IL header')
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from('<I',c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from('<i',c,o+1)[0]!=t:raise ProofError(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from('<i',c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError('DLL SHA '+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=mcode(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+' body')
  cs[n]=c
 c=cs['ConsumeSP']
 tok(c,0,0x7E,0x0400576C,'Consume MatchMain.inst');tok(c,7,0x28,0x0A00002A,'Consume implicit');br(c,12,0x3A,18,'Consume match present')
 tok(c,19,0x7B,0x04005751,'Consume isTimeCounting');br(c,24,0x3A,30,'Consume time counting');tok(c,31,0x7B,0x04005753,'Consume isMatchEnd');br(c,36,0x39,42,'Consume not ended')
 if c[42:45]!=bytes([0x02,0x03,0x65]):raise ProofError('Consume negated input')
 tok(c,45,0x28,0x06004ECF,'Consume AddSP')
 c=cs['RecoverSP']
 tok(c,0,0x7E,0x0400576C,'Recover MatchMain.inst');tok(c,7,0x28,0x0A00002A,'Recover implicit');br(c,12,0x39,41,'Recover no match')
 tok(c,18,0x7B,0x04005751,'Recover time');br(c,23,0x3A,29,'Recover time counting');tok(c,30,0x7B,0x04005753,'Recover ended');br(c,35,0x39,41,'Recover not ended')
 tok(c,42,0x7B,0x0400605A,'Recover isBleeding');br(c,47,0x39,69,'Recover split');tok(c,53,0x7B,0x04005FB3,'Recover Wres bleeding');tok(c,58,0x7B,0x04001096,'Recover bleeding field');br(c,64,0x38,81,'Recover join')
 tok(c,70,0x7B,0x04005FB3,'Recover Wres');tok(c,75,0x7B,0x04001095,'Recover normal field');tok(c,82,0x7E,0x04006082,'Recover table')
 if c[87:92]!=bytes([0x07,0x98,0x5A,0x10,0x01]):raise ProofError('Recover table multiply')
 tok(c,94,0x28,0x06004ECF,'Recover AddSP')
 c=cs['InvokeUkeBonus']
 tok(c,1,0x7B,0x0400606D,'Uke invoked read');br(c,6,0x39,12,'Uke first');tok(c,14,0x7D,0x0400606D,'Uke invoked set');tok(c,21,0x7B,0x04005FC7,'Uke recovery')
 if c[26:29]!=bytes([0x18,0x5B,0x6B]):raise ProofError('Uke integer half')
 tok(c,29,0x28,0x06004ECF,'Uke AddSP');tok(c,36,0x7D,0x04005FC9,'Uke timer zero')
 for read,imm,branch,store,threshold in [(42,47,52,70,7680),(76,81,86,104,15360),(110,115,120,138,30720)]:
  tok(c,read,0x7B,0x04005FC7,'Uke threshold read');i4(c,imm,threshold,'Uke threshold');br(c,branch,0x3E,store+5,'Uke ble');tok(c,store-11,0x7B,0x04005FC9,'Uke timer read');i4(c,store-6,1800,'Uke +1800');tok(c,store,0x7D,0x04005FC9,'Uke timer store')
 if c[143]!=0x2A:raise ProofError('Uke ret')
 return {'dll_sha256':got,'methods':{n:{'code_size':len(cs[n]),'code_sha256':M[n][2]} for n in M}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dll',required=True);ap.add_argument('--out');a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
  print(json.dumps(r,indent=2,sort_keys=True));print('PROVE_PLAYER_SP_SIDE_HELPERS: PASS');return 0
 except (OSError,ValueError,ProofError) as e:print('PROVE_PLAYER_SP_SIDE_HELPERS: FAIL');print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
