#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F28C
SIZE=654
CODE_SHA="51600ca58d83133003e36ec3afd834efa865af3cd33749c16af5e5f0e68d9a1d"
EH_HEX="011000000000d10019ea0009c2000001"
EH_SHA="70456e60bd6570383da3640a430a402719684d70d8183af136792f90f11df539"
AWAKE_RVA=0x0006F11E
AWAKE_SHA="bcee56df40b0e166d956e871a4b165a2e11eed714129aff4e22590ffbe441aae"

class E(RuntimeError): pass

def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\\0\\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]
    z=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+z
    out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out

def method(pe,ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz:
            o=rp+rva-va
            break
    else:
        raise E("rva")
    b=pe[o]
    if b&3==2:
        return {"offset":o,"header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4
    n=struct.unpack_from("<I",pe,o+4)[0]
    return {"offset":o,"header":h,"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],
            "local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}

def tok(c,o,op,t,label):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:
        raise E(label)

def br(c,o,op,target,label):
    if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:
        raise E(label)

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--dll",required=True)
    x=a.parse_args()
    pe=Path(x.dll).read_bytes()
    if hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("dll")
    ss=sections(pe)
    m=method(pe,ss,RVA)
    c=m["code"]
    awake=method(pe,ss,AWAKE_RVA)["code"]
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise E("Parse body")
    if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=6 or m["local_sig"]!=0x1100034E:
        raise E("Parse header")
    if hashlib.sha256(awake).hexdigest()!=AWAKE_SHA: raise E("FACT-0184 Awake body")

    tok(c,0x0000,0x28,0x0A00055A,"start time")
    tok(c,0x0006,0x72,0x7000BE72,"resource path")
    tok(c,0x000B,0x28,0x0A0006DA,"Resources.Load")
    tok(c,0x0010,0x75,0x010000E4,"TextAsset cast")
    tok(c,0x0017,0x6F,0x0A0006DB,"TextAsset.text")
    tok(c,0x001C,0x73,0x0A0006DC,"StringReader ctor")
    tok(c,0x0022,0x73,0x0A00078C,"List String-array ctor")
    tok(c,0x0029,0x6F,0x0A0006DD,"ReadLine")
    tok(c,0x0040,0x8D,0x010000CF,"Char array")
    if c[0x0045:0x004A]!=bytes([0x25,0x16,0x1F,0x09,0x9D]): raise E("raw tab delimiter")
    tok(c,0x004A,0x6F,0x0A0000A4,"String.Split")
    tok(c,0x004F,0x6F,0x0A00078D,"row Add")
    tok(c,0x0062,0x6F,0x0A00078E,"outer get_Item")
    tok(c,0x006C,0x72,0x70007D24,"outer end string")
    tok(c,0x0071,0x28,0x0A00016A,"outer String.Equals")
    br(c,0x0076,0x39,0x0080,"outer sentinel false")
    br(c,0x007B,0x38,0x027E,"outer sentinel exit")

    tok(c,0x0080,0x73,0x060011E2,"FACT-0182 WrestlerVoiceInfo ctor")
    tok(c,0x008C,0x6F,0x0A00078E,"type get_Item")
    tok(c,0x0096,0x28,0x0A0006DE,"type Int32.Parse")
    tok(c,0x009B,0x7D,0x040011DD,"type field")

    tok(c,0x00B7,0x6F,0x0A00078E,"dlc get_Item")
    tok(c,0x00C1,0x28,0x0A000015,"dlc IsNullOrEmpty")
    br(c,0x00C6,0x3A,0x011C,"dlc empty gate")
    tok(c,0x00D4,0x6F,0x0A00078E,"dlc parse get_Item")
    tok(c,0x00DE,0x28,0x0A0006DE,"dlc Int32.Parse")
    br(c,0x00E5,0xDD,0x00F3,"dlc parse leave")
    if c[0x00EA:0x00EE]!=bytes([0x26,0x17,0x13,0x09]): raise E("dlc catch flag")
    br(c,0x00EE,0xDD,0x00F3,"dlc catch leave")
    br(c,0x00F6,0x40,0x010B,"dlc raw 1 test")
    tok(c,0x00FD,0x7B,0x040011DE,"dlc field")
    if c[0x0102:0x0106]!=bytes([0x11,0x08,0x17,0x9C]): raise E("dlc true write")
    br(c,0x010D,0x39,0x0115,"dlc raw zero test")
    if c[0x0112:0x0115]!=bytes([0x17,0x13,0x09]): raise E("dlc nonzero flag")
    br(c,0x0117,0x39,0x011C,"converging local9 branch")
    if c[0x0128:0x012C]!=bytes([0x11,0x08,0x1F,0x10]): raise E("raw 16 loop bound")
    br(c,0x012C,0x3F,0x00B4,"dlc loop")

    tok(c,0x0140,0x7D,0x040011DF,"parentFolder field")
    tok(c,0x015A,0x7D,0x040011E0,"fileNamePrefix field")
    tok(c,0x0174,0x28,0x0A0006DE,"sortOrder Int32.Parse")
    tok(c,0x0179,0x7D,0x040011E2,"sortOrder field")
    tok(c,0x0186,0x7B,0x040011E1,"name field #0")
    if c[0x0198:0x019A]!=bytes([0x9A,0xA2]): raise E("name[0] write")
    tok(c,0x019C,0x7B,0x040011E1,"name field #1")
    if c[0x01AE:0x01B0]!=bytes([0x9A,0xA2]): raise E("name[1] write")

    tok(c,0x01B9,0x6F,0x0A00078E,"attr sentinel get_Item")
    tok(c,0x01C1,0x72,0x70007D24,"attr end string")
    tok(c,0x01C6,0x28,0x0A00016A,"attr String.Equals")
    br(c,0x01CB,0x39,0x01D5,"attr sentinel false")
    br(c,0x01D0,0x38,0x0266,"attr sentinel exit")
    tok(c,0x01D5,0x73,0x060011E1,"FACT-0182 WrestlerVoiceAttr ctor")
    tok(c,0x01DE,0x7B,0x040011DB,"description #0")
    tok(c,0x01F4,0x7B,0x040011DB,"description #1")
    if c[0x020A]!=0x15: raise E("default cheer raw -1")
    tok(c,0x020B,0x7D,0x040011DC,"cheerVoice default")
    tok(c,0x0213,0x6F,0x0A00078E,"cheer cell get_Item")
    tok(c,0x021D,0x28,0x0A000015,"cheer IsNullOrEmpty")
    br(c,0x0222,0x3A,0x024D,"cheer empty gate")
    if c[0x0236]!=0x18: raise E("ParsePrm raw dgt 2")
    tok(c,0x0239,0x7B,0x040011DD,"ParsePrm type field")
    tok(c,0x023E,0x72,0x7000BEA8,"ParsePrm error string")
    tok(c,0x0243,0x28,0x060011E9,"FACT-0185 ParsePrm_Int")
    tok(c,0x0248,0x7D,0x040011DC,"cheerVoice parsed")
    tok(c,0x024F,0x7B,0x040011E3,"attr list")
    tok(c,0x0256,0x6F,0x0A00078F,"attr Add")
    tok(c,0x0267,0x7B,0x040011E7,"manager voice list")
    tok(c,0x026E,0x6F,0x0A000790,"voice Add")
    if c[0x0275:0x0279]!=bytes([0x1A,0x58,0x13,0x05]): raise E("raw outer step 4")
    br(c,0x0279,0x38,0x005C,"outer loop back")

    tok(c,0x027E,0x28,0x0A00055A,"end time")
    if c[0x0283:0x0287]!=bytes([0x06,0x59,0x13,0x0C]): raise E("elapsed local")
    tok(c,0x0288,0x28,0x0A0006DF,"Resources.UnloadAsset")
    if c[0x028D]!=0x2A: raise E("ret")

    end=(m["offset"]+m["header"]+len(c)+3)&~3
    eh=pe[end:end+16]
    if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA: raise E("EH")
    tok(awake,0x0037,0x28,0x060011EA,"FACT-0184 Awake caller")
    print("PROVE_WRESTLER_VOICE_INFO_MANAGER_PARSE: PASS")

if __name__=="__main__":
    main()
