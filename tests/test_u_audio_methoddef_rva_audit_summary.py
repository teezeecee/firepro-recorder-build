#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_methoddef_rva_audit.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_METHODDEF_RVA_AUDIT_V1"
assert s["methoddef_row_size"]==18
rows={x["token"]:x for x in s["methods"]}
expected={
"0x060052CA":("0x0032567D",13,"62a68c749da17a7c536b2ef155fd300637ffd8bd582da8979c28fdd87bf83d1c"),
"0x060052CB":("0x0032568B",7,"f0eb7b6d2625782d43a08476d93acb464e82bc45c00d660925f2176d82bc8c4b"),
"0x060052D0":("0x003256D4",86,"5524703abb8912537cca2bf60cf25fdcde63df8bcc2ea51a0db76d5dc8e858c4"),
"0x060052D6":("0x00325776",41,"49f83f2ff33655f9bece0288383a552b4e5a31346d16547fcfd1028ecfdc7b0b"),
"0x060052DC":("0x00325827",13,"e3434a65b5c1a9c14959c686924c525e57f68f1cf3fbde7c02a25819e891480c"),
"0x060052E0":("0x0032587C",8,"bf7afe343990f70067b2d0a5f418a180d7f1abee664827c4b4e6e18940403ca7"),
"0x060052E4":("0x00325970",65,"b5b74da6ab2322d1895635e2add04dd52f9ee9ca4a3846825a9b6fe4631e3ef4"),
"0x060052E6":("0x003259C8",141,"3ff6f18fdb7ed86c92f309f6496f6d7fc3a7cee75b55c9174345fac0efaeee4c"),
"0x060052E7":("0x00325A80",564,"25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"),
"0x060052EE":("0x00325E6A",13,"124f59a872afec501c29839a33e627e58a6c5339d59456ad7f66f6b7323e237d")
}
assert set(rows)==set(expected)
for t,(rva,size,sha) in expected.items():
    assert (rows[t]["rva"],rows[t]["body_size"],rows[t]["body_sha256"])==(rva,size,sha)
    assert len(bytes.fromhex(rows[t]["methoddef_row_hex"]))==18
print("DLL U AUDIO METHODDEF RVA AUDIT SUMMARY: PASS")
