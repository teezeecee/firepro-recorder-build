#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prove_weaponman_get_weapon_obj as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
TARGET=0x06006AC9
TARGET_RVA=0x0043541C
TARGET_ROW='1c5443000000860000cf0a00b8370300ad4d'
TARGET_SIG='2005010811190c11a85c11a768'
TARGET_BODY=bytes.fromhex('020328c86a00060a06282a00000a3a010000002a0604050e040e056fb86a00062a')
TARGET_SHA='edcc7cf0273d8a9e58e2e252323436fb039630779892b4c0e2e9654eddab7f76'
LOCAL_SIG_TOKEN=0x11001074
LOCAL_SIG='070112b508'
GET_WEAPON_OBJ=0x06006AC8
OP_IMPLICIT=0x0A00002A
WEAPON_DROP=0x06006AB8
WEAPON_DROP_RVA=0x00434C48
WEAPON_DROP_SIZE=167
WEAPON_DROP_SHA='eac3737037ba8ea767d588f6988426f6fd38567d37400dda6e58cfdc20ccc25e'
PLAYER_DROP=0x06004EDF
PLAYER_DROP_RVA=0x002E1A44
PLAYER_DROP_ROW='441a2e000000860095250a005c480000553a'
PLAYER_DROP_SIG='200001'
PLAYER_DROP_SIZE=94
PLAYER_DROP_SHA='1ef3a7e1cc92cacab56a77fe83cec0ea5ff67e1c740031a8e99291013da59457'
PLAYER_DROP_BODY=bytes.fromhex('027b0b600004163c010000002a027bb05f000428644900060a027baa5f00040b1201257b5600000a225555353f587d5600000a7eeab60004027b0b60000407027caa5f00047b5600000a027bee5f0004066fc96a000602157d0b6000042a')
PLAYER_WEAPON_IDX=0x0400600B
WITNESS_BYTES=1548
WITNESS_SHA='e1d7d7d17a5a18da4ce9110cd4878d2bcdafc6441ca866580f0f4cd24c9c21cf'
FIELDS=['parent_pre_line','parent_post_line','child_pre_line','child_post_line','tick','parent_pre_seq','child_pre_seq','child_post_seq','parent_post_seq','parent_owner_slot','parent_instance','child_owner_slot','child_instance','parent_pre_weaponIdx','child_pre_weaponIdx','child_post_weaponIdx','parent_post_weaponIdx','child_args']

class E(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()

def token_at(c,off,opcode,token,label):
    if c[off]!=opcode or struct.unpack_from('<I',c,off+1)[0]!=token: raise E(label)

def method_row_hex(pe,streams,hs,rows,p,token):
    _,_,_,_,sizes,offs=base.setup_tables(pe,streams,hs,rows,p)
    rid=token&0xffffff; o=offs[6]+(rid-1)*sizes[6]
    return pe[o:o+sizes[6]].hex()

def local_sig_blob(pe,streams,hs,rows,p,token):
    _,blobsz,_,_,sizes,offs=base.setup_tables(pe,streams,hs,rows,p)
    rid=token&0xffffff; o=offs[17]+(rid-1)*sizes[17]
    ix,_=base.rd(pe,o,blobsz)
    return base.blob(pe,streams['#Blob'][0],ix).hex()

def param_names(pe,streams,hs,rows,p,token):
    strsz,blobsz,ix,cix,sizes,offs=base.setup_tables(pe,streams,hs,rows,p)
    sb=streams['#Strings'][0]
    def string(i):
        e=pe.index(b'\0',sb+i); return pe[sb+i:e].decode()
    rid=token&0xffffff; o=offs[6]+(rid-1)*sizes[6]; pos=o+8
    _,pos=base.rd(pe,pos,strsz); _,pos=base.rd(pe,pos,blobsz); first,pos=base.rd(pe,pos,ix(8))
    if rid<rows[6]:
        no=offs[6]+rid*sizes[6]; npos=no+8
        _,npos=base.rd(pe,npos,strsz); _,npos=base.rd(pe,npos,blobsz); nxt,npos=base.rd(pe,npos,ix(8))
    else: nxt=rows[8]+1
    out=[]
    for prid in range(first,nxt):
        po=offs[8]+(prid-1)*sizes[8]
        _,seq=struct.unpack_from('<HH',pe,po)
        ni,_=base.rd(pe,po+4,strsz)
        out.append((seq,string(ni)))
    return out

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.sections(pe); streams,hs,rows,p=base.metadata(pe,ss,q); owner=base.build_method_owner(pe,streams,hs,rows,p)
    md=base.parse_method_row(pe,streams,hs,rows,p,TARGET&0xffffff,owner)
    if (md['type'],md['name'],md['rva'],md['sig'])!=('WeaponMan','Drop',TARGET_RVA,TARGET_SIG): raise E('target metadata')
    if method_row_hex(pe,streams,hs,rows,p,TARGET)!=TARGET_ROW: raise E('target row')
    if param_names(pe,streams,hs,rows,p,TARGET)!=[(1,'idx'),(2,'p'),(3,'gy'),(4,'zone'),(5,'dir')]: raise E('target params')
    m=base.method(pe,ss,TARGET_RVA); c=m['code']
    if m['format']!='fat' or m['flags']!=0x13 or m['max_stack']!=5 or m['local_sig']!=LOCAL_SIG_TOKEN: raise E('target header')
    if local_sig_blob(pe,streams,hs,rows,p,LOCAL_SIG_TOKEN)!=LOCAL_SIG: raise E('local sig')
    if len(c)!=33 or hashlib.sha256(c).hexdigest()!=TARGET_SHA or c!=TARGET_BODY: raise E('target body')
    if c[0:2]!=bytes([0x02,0x03]): raise E('this/idx load')
    token_at(c,0x02,0x28,GET_WEAPON_OBJ,'GetWeaponObj call')
    if c[0x07:0x09]!=bytes([0x0A,0x06]): raise E('local store/load')
    token_at(c,0x09,0x28,OP_IMPLICIT,'Object.op_Implicit')
    if c[0x0E]!=0x3A or 0x0E+5+struct.unpack_from('<i',c,0x0F)[0]!=0x14: raise E('object gate branch')
    if c[0x13]!=0x2A: raise E('null return')
    if c[0x14:0x1B]!=bytes([0x06,0x04,0x05,0x0E,0x04,0x0E,0x05]): raise E('Weapon.Drop args')
    token_at(c,0x1B,0x6F,WEAPON_DROP,'Weapon.Drop callvirt')
    if c[0x20]!=0x2A: raise E('target ret')
    wd=base.parse_method_row(pe,streams,hs,rows,p,WEAPON_DROP&0xffffff,owner)
    wc=base.method(pe,ss,WEAPON_DROP_RVA)['code']
    if wd['type']!='Weapon' or wd['name']!='Drop' or wd['rva']!=WEAPON_DROP_RVA or len(wc)!=WEAPON_DROP_SIZE or hashlib.sha256(wc).hexdigest()!=WEAPON_DROP_SHA: raise E('Weapon.Drop identity')
    pd=base.parse_method_row(pe,streams,hs,rows,p,PLAYER_DROP&0xffffff,owner)
    pc=base.method(pe,ss,PLAYER_DROP_RVA)['code']
    if (pd['type'],pd['name'],pd['rva'],pd['sig'])!=('Player','DropWeapon',PLAYER_DROP_RVA,PLAYER_DROP_SIG): raise E('Player.DropWeapon metadata')
    if method_row_hex(pe,streams,hs,rows,p,PLAYER_DROP)!=PLAYER_DROP_ROW: raise E('Player.DropWeapon row')
    if len(pc)!=PLAYER_DROP_SIZE or hashlib.sha256(pc).hexdigest()!=PLAYER_DROP_SHA or pc!=PLAYER_DROP_BODY: raise E('Player.DropWeapon body')
    if pc[0]!=0x02: raise E('Player.DropWeapon this')
    token_at(pc,0x01,0x7B,PLAYER_WEAPON_IDX,'Player.weaponIdx read')
    if pc[0x06]!=0x16 or pc[0x07]!=0x3C or 0x07+5+struct.unpack_from('<i',pc,0x08)[0]!=0x0D or pc[0x0C]!=0x2A: raise E('Player.DropWeapon negative gate')
    token_at(pc,0x51,0x6F,TARGET,'Player.DropWeapon -> WeaponMan.Drop')
    if pc[0x56:0x58]!=bytes([0x02,0x15]): raise E('Player.DropWeapon reset prefix')
    token_at(pc,0x58,0x7D,PLAYER_WEAPON_IDX,'Player.weaponIdx reset')
    if pc[0x5D]!=0x2A: raise E('Player.DropWeapon ret')
    needle=struct.pack('<I',TARGET); refs=[]
    for rid in range(1,rows[6]+1):
        x=base.parse_method_row(pe,streams,hs,rows,p,rid,owner)
        if not x['rva']: continue
        try: code=base.method(pe,ss,x['rva'])['code']
        except Exception: continue
        for i in range(len(code)-4):
            if code[i] in (0x28,0x6F) and code[i+1:i+5]==needle:
                refs.append((x['type'],x['name'],0x06000000|rid,x['rva'],i,code[i]))
    if refs!=[('Player','DropWeapon',PLAYER_DROP,PLAYER_DROP_RVA,0x51,0x6F)]: raise E('inbound map '+repr(refs))
    return {'code_size':len(c),'code_sha256':TARGET_SHA,'inbound_reference_count':1,'weapon_drop_code_sha256':WEAPON_DROP_SHA}

def verify_r6(path):
    if sha_path(path)!=R6_SHA: raise E('R6 identity')
    with zipfile.ZipFile(path) as z:
        bad=z.testzip()
        if bad: raise E('ZIP CRC '+bad)
        names=[n for n in z.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1: raise E('event_trace count')
        name=names[0]
        with z.open(name) as f:
            if hashlib.sha256(f.read()).hexdigest()!=EVENT_SHA: raise E('event trace identity')
        stack=[]; nodes=[]
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding='utf-8-sig',newline=''),delimiter='\t')
            for line,row in enumerate(rd,start=2):
                ph=row['phase']
                if ph=='MARK': continue
                if ph=='PRE':
                    node={'line':line,'row':dict(row),'post':None,'post_line':None,'children':[],'parent':stack[-1] if stack else None}
                    if stack: stack[-1]['children'].append(node)
                    stack.append(node); nodes.append(node)
                elif ph=='POST':
                    if not stack: raise E('POST without PRE')
                    node=stack.pop()
                    if node['row']['method']!=row['method'] or node['row']['instance']!=row['instance']: raise E('non-LIFO trace')
                    node['post']=dict(row); node['post_line']=line
        if stack: raise E('unterminated trace')
    parents=[n for n in nodes if n['row']['method']=='Player.DropWeapon']
    child_all=[n for n in nodes if n['row']['method']=='Weapon.Drop']
    wrapper_rows=[n for n in nodes if n['row']['method']=='WeaponMan.Drop']
    neg=[p for p in parents if int(p['row']['weaponIdx'])<0]
    nonneg=[p for p in parents if int(p['row']['weaponIdx'])>=0]
    if (len(parents),len(child_all),len(wrapper_rows),len(neg),len(nonneg))!=(923,11,0,912,11): raise E('R6 method counts')
    if any(p['children'] for p in neg): raise E('negative parent children')
    records=[]
    for p in nonneg:
        if len(p['children'])!=1 or p['children'][0]['row']['method']!='Weapon.Drop': raise E('nonnegative child shape')
        c=p['children'][0]
        r={
          'parent_pre_line':p['line'],'parent_post_line':p['post_line'],'child_pre_line':c['line'],'child_post_line':c['post_line'],
          'tick':p['row']['tick'],'parent_pre_seq':p['row']['seq'],'child_pre_seq':c['row']['seq'],'child_post_seq':c['post']['seq'],'parent_post_seq':p['post']['seq'],
          'parent_owner_slot':p['row']['owner_slot'],'parent_instance':p['row']['instance'],'child_owner_slot':c['row']['owner_slot'],'child_instance':c['row']['instance'],
          'parent_pre_weaponIdx':p['row']['weaponIdx'],'child_pre_weaponIdx':c['row']['weaponIdx'],'child_post_weaponIdx':c['post']['weaponIdx'],'parent_post_weaponIdx':p['post']['weaponIdx'],'child_args':c['row']['args']
        }
        if r['parent_owner_slot']!=r['child_owner_slot']: raise E('owner relation')
        if r['parent_pre_weaponIdx']!=r['child_pre_weaponIdx']: raise E('pre index relation')
        if r['child_pre_weaponIdx']!=r['child_post_weaponIdx']: raise E('child index mutation')
        if r['parent_post_weaponIdx']!='-1': raise E('parent post index')
        if not (int(r['child_pre_seq'])==int(r['parent_pre_seq'])+2 and int(r['child_post_seq'])==int(r['child_pre_seq'])+2 and int(r['parent_post_seq'])==int(r['child_post_seq'])+2): raise E('seq relation')
        records.append(r)
    if Counter(r['parent_pre_weaponIdx'] for r in records)!=Counter({'3':3,'7':2,'5':2,'2':2,'0':1,'6':1}): raise E('index counts')
    if Counter(r['child_args'] for r in records)!=Counter({'Vector3 | 1 | InRing | Left':8,'Vector3 | 1 | InRing | Right':3}): raise E('arg counts')
    witness=''.join('\t'.join(str(r[f]) for f in FIELDS)+'\n' for r in records).encode('utf-8')
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=WITNESS_BYTES or wsha!=WITNESS_SHA: raise E('witness digest')
    return {'player_drop_weapon_count':923,'negative_count':912,'nonnegative_count':11,'weapon_drop_count':11,'witness_byte_count':len(witness),'witness_sha256':wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--dll',required=True); ap.add_argument('--r6',required=True); a=ap.parse_args()
    try:
        result={'dll':verify_dll(a.dll),'r6':verify_r6(a.r6)}
        print(json.dumps(result,indent=2,sort_keys=True))
        print('PROVE_WEAPONMAN_DROP: PASS')
        return 0
    except (OSError,ValueError,KeyError,IndexError,zipfile.BadZipFile,E) as e:
        print('PROVE_WEAPONMAN_DROP: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
