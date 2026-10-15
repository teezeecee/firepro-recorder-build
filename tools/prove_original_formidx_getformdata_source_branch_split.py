#!/usr/bin/env python3
"""FACT-0358 original FormDataMan.GetFormData byte-bound IL and source formIdx branch split."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/'canonical/witnesses/RESPANEL-001/original_23037_formidx_getformdata_branch_source_split.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def digest(v):return sha(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8'))
def chk(q,msg):
    if not q:raise AssertionError(msg)
def extract_method(dll,rva):
    pe=struct.unpack_from('<I',dll,0x3c)[0]
    chk(dll[pe:pe+4]==bytes((0x50,0x45,0,0)),'original DLL PE header')
    n=struct.unpack_from('<H',dll,pe+6)[0]
    cursor=pe+24+struct.unpack_from('<H',dll,pe+20)[0]
    off=None
    for j in range(n):
        vs,va,rs,rp=struct.unpack_from('<IIII',dll,cursor+40*j+8)
        if va<=rva<va+max(vs,rs):off=rp+rva-va;break
    chk(off is not None,'original MethodDef RVA mapped to PE body')
    header=struct.unpack_from('<H',dll,off)[0]
    hdr=(header>>12)*4;size=struct.unpack_from('<I',dll,off+4)[0]
    chk(header&3==3 and hdr==12 and size==84,'original method header and body size')
    return dll[off+hdr:off+hdr+size]
def prove(dllfile,packed,report,w):
    d=Path(dllfile).read_bytes();p=Path(packed).read_bytes();r=Path(report).read_bytes()
    src=w['original_panel'];orig=w['original_dll'];o=w['observed']
    chk((len(d),sha(d))==(orig['bytes'],orig['sha256']),'matching original retail DLL SHA')
    chk((len(p),sha(p))==(src['bytes'],src['sha256']),'exact original 440 source panel SHA')
    chk((len(r),sha(r))==(src['companion_bytes'],src['companion_sha256']),'exact original GGM source report SHA')
    il=extract_method(d,int(orig['rva'],16))
    chk((len(il),sha(il))==(orig['code_bytes'],orig['code_sha256']),'original GetFormData 84-byte IL SHA')
    for item in orig['source_windows']:
        lo=int(item['start_il'],16);hi=int(item['end_exclusive_il'],16)
        chk(sha(il[lo:hi])==item['sha256'],'original IL source bounded window '+item['name'])
    chk([(il[p0],int.from_bytes(il[p0+1:p0+5],'little',signed=True)) for p0 in (6,15,29,42,53)]==[(0x3a,2),(0x3f,14),(0x3f,2),(0x3f,28),(0x3d,17)],'original exact branch opcodes and relative operands')
    chk(il[0x25]==0x20 and int.from_bytes(il[0x26:0x2a],'little')==37000,'first 37000 source branch constant')
    chk(il[0x30]==0x20 and int.from_bytes(il[0x31:0x35],'little')==37999,'37999 source branch upper limit')
    chk(il[0x43]==0x20 and int.from_bytes(il[0x44:0x48],'little')==37000,'block lookup original subtraction constant')
    for at,token in [(1,0x040026dd),(22,0x040026dd),(59,0x040026de),(76,0x040026dd)]:
        chk(il[at]==0x7b and int.from_bytes(il[at+1:at+5],'little')==token,'original field token read '+str(at))
    chk(il[0x40:0x43]==bytes((4,0x9a,3)),'block field caller arg2 indexing then input')
    chk(il[0x48:0x4b]==bytes((0x59,0x9a,0x2a)),'block index subtraction and return')
    chk(il[0x51:0x54]==bytes((3,0x9a,0x2a)),'primary array source index and return')
    chk(il[0x0b:0x0d]==bytes((0x14,0x2a)) and il[0x22:0x24]==bytes((0x14,0x2a)),'original null return gates')
    entries=json.loads(r)['Entries'];chk(len(entries)==440,'all original GGM source objects')
    rows=[];segs=0;count=collections.Counter();objects=collections.defaultdict(set);unique=collections.defaultdict(set)
    for entry in entries:
        name=entry['ResourceName'].rsplit('/',1)[-1]
        obj=p[entry['PackedOffset']:entry['PackedOffset']+entry['OriginalByteLength']]
        chk(sha(obj)==entry['BodySha256'],'exact original source object SHA '+name)
        n=struct.unpack_from('<I',obj)[0];ofs=((4+n+3)&~3)+4;body=obj[ofs:-4]
        chk(ofs==entry['ObservedEmbeddedDataOffset'] and sha(body)==entry['ObservedEmbeddedDataSha256'],'original embedded source SHA '+name)
        chk(body[:2]==b'RS' and (len(body)-64)%12==0,'exact source RS form region')
        prev=0
        for slot,end in enumerate(body[48:64]):
            chk(prev<=end<=(len(body)-64)//12,'source vector bounds')
            if end>prev:
                start=64+12*prev;forms=body[start]
                chk(end-prev==forms+1,'original header form count')
                segs+=1
                for form in range(forms):
                    at=start+12*(form+1);part=body[at:at+12]
                    chk(len(part)==12,'original form source 12 byte boundary')
                    ix=(part[2]<<8)|part[3]
                    branch='block' if 37000<=ix<=37999 else 'regular'
                    operand=ix-37000 if branch=='block' else ix
                    row={'index':entry['SourceIndex'],'path_id':entry['PathId'],'name':name,'slot':slot,'form':form,'source_offset':at,'formIdx':ix,'lookup_branch':branch,'array_index_operand':operand}
                    rows.append(row);count[branch]+=1;objects[branch].add(entry['PathId']);unique[branch].add(ix)
            prev=end
        chk(prev==(len(body)-64)//12,'complete original segment span')
    chk(segs==o['source_segment_headers']==1347 and len(rows)==o['total_original_form_records']==23037,'complete original 23037 source rows')
    chk(digest(rows)==o['original_form_branch_rows_sha256'],'all original source index/group rows SHA')
    chk((count['regular'],count['block'])==(o['regular_records'],o['block_range_records'])==(19010,4027),'exact original branch range counts')
    chk((len(unique['regular']),len(unique['block']))==(o['regular_distinct_formIdx_inputs'],o['block_distinct_formIdx_inputs'])==(6215,999),'original distinct source inputs')
    chk((len(objects['regular']),len(objects['block']))==(o['regular_source_objects'],o['block_source_objects'])==(404,179),'original source object memberships')
    chk((min(unique['regular']),max(unique['regular']),min(unique['block']),max(unique['block']))==(100,36999,37000,37998),'original source index group ranges')
    for anchor in w['anchors']:
        chk(anchor in rows,'exact original source branch anchor '+anchor['name'])
    return {'fact':'FACT-0358','getformdata_il_bytes':84,'source_form_records':len(rows),'regular':count['regular'],'block':count['block'],'branch_rows_sha256':digest(rows),'runtime_eligible':False}
if __name__=='__main__':
    arg=argparse.ArgumentParser()
    arg.add_argument('--dll',required=True);arg.add_argument('--packed',required=True);arg.add_argument('--report',required=True)
    a=arg.parse_args()
    print(json.dumps(prove(a.dll,a.packed,a.report,json.loads(W.read_text())),sort_keys=True))
    print('FACT0358_ORIGINAL_GETFORMDATA_SOURCE_BRANCH_SPLIT_PASS')
