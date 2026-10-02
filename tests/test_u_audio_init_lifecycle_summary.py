#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_init_lifecycle.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_INIT_LIFECYCLE_V1"
c=s["dll"]["constructor"]; a=s["dll"]["awake"]
assert (c["token"],c["rva"],c["code_size"],c["code_sha256"])==("0x060052C8","0x00325627",29,"b3886117f8449c5a0bb1c948786b6cf3ecbfd14d7caee2594f9fb9cdcdc30b5e")
assert c["body_hex"]=="02220000803f7df0870004027ebd0f000a7df287000402280e00000a2a"
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x060052C9","0x00325648",41,"ff82e2f96702dc7b19840d6fe9cfa849d45c0fd7a749b317b93de5377869aa7e")
assert (a["local_signature_token"],a["local_signature_blob_hex"])==("0x1100000A","0701120d")
assert a["string"]=={"token":"0x7008EA86","value":"Sound_Manager"}
assert a["members"]["add_component_spec"]["token"]=="0x2B00004C"
assert a["members"]["add_component_spec"]["generic_type"]=="UnityEngine.AudioSource"
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO INIT LIFECYCLE SUMMARY: PASS")
