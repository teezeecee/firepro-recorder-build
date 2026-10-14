"""FACT-0326 external Unity dependency-table source regression (no proprietary bytes)."""
import json
from pathlib import Path
R = Path(__file__).resolve().parents[1]
w = json.loads((R/"canonical/witnesses/GGM-001/external_fileid_mappings.summary.json").read_text())
f = json.loads((R/"canonical/facts/FACT-0326-original-unity-external-file-references.json").read_text())
old = json.loads((R/"canonical/witnesses/GGM-001/graphics_settings_full_object.summary.json").read_text())
reg = json.loads((R/"canonical/transition_registry.json").read_text())
manifest = json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"], f["status"]) == ("FACT-0326", "PROVEN_PACKED_DATA")
assert w["dataset_id"] == "UNITY_GGM_EXTERNAL_PPTR_FILEID_TABLE_V1"
assert w["source_ids"] == ["GGM-001"]
src = next(s for s in manifest["sources"] if s["source_id"] == "GGM-001")
assert src["canonical_eligible"] and src["sha256"] == w["original_file"]["sha256"]
tab = w["external_reference_table"]
refs = w["references"]
assert (tab["count"], tab["count_field_offset"], tab["first_row_offset"], tab["rows_end_offset"], tab["metadata_end_offset"]) == (11, 908, 912, 1398, 1399)
assert len(refs) == 11 and [x["file_id"] for x in refs] == list(range(1,12))
assert refs[0]["start_offset"] == 912
assert all(a["end_offset"] == b["start_offset"] for a,b in zip(refs, refs[1:]))
assert refs[-1]["end_offset"] == tab["rows_end_offset"]
assert all(x["asset_path"] == "" and x["type"] == 0 and len(x["guid_hex"]) == 32 for x in refs)
assert [x["path"] for x in refs] == [
    "globalgamemanagers.assets", "library/unity default resources",
    "resources/unity_builtin_extra", "sharedassets0.assets", "resources.assets",
    "sharedassets49.assets", "sharedassets4.assets", "sharedassets55.assets",
    "sharedassets59.assets", "sharedassets2.assets", "sharedassets5.assets"]
assert refs[1]["guid_hex"] == "00000000000000000e00000000000000"
assert refs[2]["guid_hex"] == "00000000000000000f00000000000000"
assert all(x["guid_hex"] == "0"*32 for i,x in enumerate(refs) if i not in (1,2))
assert old["object"]["class_id"] == 30 and old["object"]["path_id"] == 7
assert all(x["file_id"] == 3 for x in old["builtin_shader_settings"])
assert len(old["builtin_shader_settings"]) == w["graphics_settings_join"]["builtin_shader_references"] == 8
assert refs[old["builtin_shader_settings"][0]["file_id"]-1]["path"] == w["graphics_settings_join"]["mapped_external_path"]
assert refs[old["sprite_default_material"]["file_id"]-1]["path"] == w["graphics_settings_join"]["sprite_default_material_mapped_path"]
assert sum(x["fact_id"]=="FACT-0326" for x in reg["families"]) == 1
entry = next(x for x in reg["families"] if x["fact_id"] == "FACT-0326")
assert entry["family_id"] == w["dataset_id"] and entry["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
assert len(set(x["family_id"] for x in reg["families"])) == len(reg["families"])
print("GLOBALGAMEMANAGERS ELEVEN EXTERNAL FILE REFERENCES: PASS")
