"""FACT-0325 original 562-byte GraphicsSettings source witness consistency regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/graphics_settings_full_object.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0325-original-unity-graphics-settings.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0325","PROVEN_PACKED_DATA")
assert w["dataset_id"]=="UNITY_GRAPHICSSETTINGS_SHADER_POINTERS_TIERS_SOURCE_V1" and w["source_ids"]==["GGM-001"]
source=next(s for s in m["sources"] if s["source_id"]=="GGM-001")
assert source["canonical_eligible"] is True and source["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(30,6,7,62176,0x102e0,562)
shader=w["builtin_shader_settings"];assert len(shader)==8
assert [s["offset"] for s in shader]==list(range(0,128,16))
assert [s["path_id"] for s in shader]==[69,74,64,63,62,75,105,102]
assert all(s["mode"]==1 and s["file_id"]==3 for s in shader)
a=w["always_included_shaders"];assert a["count"]==28 and len(a["pointers"])==28
assert [x["offset"] for x in a["pointers"]]==list(range(132,468,12))
assert a["pointers"][0]["file_id"]==3 and a["pointers"][-1]["path_id"]==68
assert w["preloaded_shaders"]=={"count_field_offset":468,"count":0}
assert w["sprite_default_material"]=={"offset":472,"file_id":1,"path_id":2}
assert w["custom_render_pipeline"]=={"offset":484,"file_id":0,"path_id":0}
assert w["transparency"]=={"mode_offset":496,"mode":0,"axis_offset":500,"axis_float32":[0,0,1]}
assert [t["offset"] for t in w["tiers"]]==[512,528,544]
assert [t["hdrMode"] for t in w["tiers"]]==[1,1,1]
assert [t["realtimeGICPUUsage"] for t in w["tiers"]]==[25,25,50]
assert w["lighting"]=={"offset":560,"m_LightsUseLinearIntensity":0,"m_LightsUseColorTemperature":0}
assert w["lighting"]["offset"]+2==o["bytes"]
matched=[x for x in reg["families"] if x["fact_id"]=="FACT-0325"]
assert len(matched)==1 and matched[0]["family_id"]==w["dataset_id"] and matched[0]["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False and len(set(x["family_id"] for x in reg["families"]))==len(reg["families"])
print("GLOBALGAMEMANAGERS GRAPHICS SETTINGS FULL OBJECT: PASS")
