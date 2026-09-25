using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using BepInEx;
using HarmonyLib;
using UnityEngine;

namespace FireProRetailFlightRecorder
{
    [BepInPlugin("openai.firepro.retail.flightrecorder", "Fire Pro Retail Flight Recorder", "0.4.0")]
    public sealed class RecorderPlugin : BaseUnityPlugin
    {
        internal static RecorderPlugin I;
        internal readonly object Gate = new object();
        internal readonly List<object> Players = new List<object>();
        internal long Tick;
        internal bool Recording;
        internal string Home;
        internal string SessionDir;
        internal StreamWriter TickWriter;
        internal StreamWriter EventWriter;
        internal StreamWriter MarkerWriter;
        Harmony _harmony;
        int _eventSeq;
        DateTime _startedUtc;
        int _markers;
        long _tickRows;
        long _eventRows;

        void Awake()
        {
            I = this;
            Home = Environment.GetEnvironmentVariable("FIREPRO_RECORDER_HOME");
            if (String.IsNullOrEmpty(Home)) Home = Paths.PluginPath;
            Directory.CreateDirectory(Path.Combine(Home, "captures"));
            WriteStatus("READY / NOT RECORDING");
            _harmony = new Harmony("openai.firepro.retail.flightrecorder.hooks");
            InstallHooks();
            Logger.LogInfo("Flight recorder ready. F9 START, F8 MARK, F10 STOP.");
        }

        void OnDestroy()
        {
            try { StopRecording("PLUGIN_DESTROY"); } catch { }
            try { if (_harmony != null) _harmony.UnpatchSelf(); } catch { }
        }

        void Update()
        {
            if (Input.GetKeyDown(KeyCode.F9)) StartRecording();
            if (Input.GetKeyDown(KeyCode.F8)) Mark();
            if (Input.GetKeyDown(KeyCode.F10)) StopRecording("USER_F10");
        }

        void InstallHooks()
        {
            PatchNamed("MatchMain", "Update_Match", "MatchPrefix", "MatchPostfix");
            foreach (var m in new[] { "AttackHitCheck", "UpdatePlayer", "ChangeState", "ReqBasicAnm", "ReqSlotAnm", "TransitStateAfterAnm", "PostprocessEachState" })
                PatchNamed("Player", m, "EventPrefix", "EventPostfix");
            foreach (var m in new[] { "InitAnimation", "StartOpponentAnm", "StartOpponentAnmM", "UpdateAnimation" })
                PatchNamed("FormAnimator", m, "EventPrefix", "EventPostfix");
            PatchNamed("FormRen", "SetForm", "EventPrefix", "EventPostfix");
            PatchNamed("Player", "UpdateForm", "EventPrefix", "EventPostfix");
        }

        void PatchNamed(string typeName, string methodName, string prefixName, string postfixName)
        {
            try
            {
                var t = AccessTools.TypeByName(typeName);
                if (t == null) { Logger.LogWarning("Hook type not found: " + typeName); return; }
                var allMethods = t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                var methodList = new List<MethodInfo>();
                for (int i = 0; i < allMethods.Length; i++)
                    if (allMethods[i].Name == methodName) methodList.Add(allMethods[i]);
                var methods = methodList.ToArray();
                if (methods.Length == 0) { Logger.LogWarning("Hook method not found: " + typeName + "." + methodName); return; }
                var pt = typeof(Hooks);
                var pre = String.IsNullOrEmpty(prefixName) ? null : new HarmonyMethod(pt.GetMethod(prefixName, BindingFlags.Static | BindingFlags.Public));
                var post = String.IsNullOrEmpty(postfixName) ? null : new HarmonyMethod(pt.GetMethod(postfixName, BindingFlags.Static | BindingFlags.Public));
                foreach (var m in methods)
                {
                    try { _harmony.Patch(m, pre, post, null, null, null); Logger.LogInfo("Hooked " + typeName + "." + methodName + " " + Signature(m)); }
                    catch (Exception ex) { Logger.LogWarning("Hook failed " + typeName + "." + methodName + ": " + ex.Message); }
                }
            }
            catch (Exception ex) { Logger.LogWarning("Hook probe failed " + typeName + "." + methodName + ": " + ex.Message); }
        }

        internal void Seen(object o)
        {
            if (o == null) return;
            var n = o.GetType().Name;
            if (n != "Player" && !n.EndsWith("Player", StringComparison.Ordinal)) return;
            lock (Gate)
            {
                bool alreadySeen = false;
                for (int i = 0; i < Players.Count; i++)
                {
                    if (System.Object.ReferenceEquals(Players[i], o)) { alreadySeen = true; break; }
                }
                if (!alreadySeen) Players.Add(o);
            }
        }

        internal void BeginTick() { Tick++; }

        internal void EndTick()
        {
            if (!Recording) return;
            var ps = new List<object>();
            lock (Gate)
            {
                for (int i = 0; i < Players.Count && ps.Count < 2; i++)
                    if (Players[i] != null) ps.Add(Players[i]);
            }
            for (int i = 0; i < ps.Count; i++) WriteTickRow(i, ps[i]);
        }

        void StartRecording()
        {
            if (Recording) return;
            var stamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
            SessionDir = Path.Combine(Path.Combine(Home, "captures"), stamp);
            Directory.CreateDirectory(SessionDir);
            TickWriter = NewWriter(Path.Combine(SessionDir, "tick_trace.tsv"));
            EventWriter = NewWriter(Path.Combine(SessionDir, "event_trace.tsv"));
            MarkerWriter = NewWriter(Path.Combine(SessionDir, "markers.tsv"));
            TickWriter.WriteLine("tick\tseq\tplayer_slot\ttype\tState\tNextState\tPlPosX\tPlPosY\tPlPosZ\tPlDir\ttarget\tAnmHostPlayer\tCurrentSkill\tanimation\tbank\tform_index\tform_number\tFormDispDuration\tRX\tRY\tFX\tFZ\tFormRev\tisAnmPause\tisDownRequested\tDownTime\tHP\tBP\tSpirit\tWrsDP\tLastDamage\tunityX\tunityY\tunityZ");
            EventWriter.WriteLine("tick\tseq\tphase\ttype\tmethod\tinstance\targs\tstate\tnext_state\tform\tanimation\tbank");
            MarkerWriter.WriteLine("tick\tseq\tutc\tlabel");
            _startedUtc = DateTime.UtcNow; _eventSeq = 0; _markers = 0; _tickRows = 0; _eventRows = 0;
            WriteMetadata();
            Recording = true;
            WriteStatus("RECORDING - F8 mark, F10 stop");
            WriteEvent("MARK", null, "RECORDING_START", null);
        }

        void StopRecording(string reason)
        {
            if (!Recording) { WriteStatus("READY / NOT RECORDING"); return; }
            WriteEvent("MARK", null, "RECORDING_STOP:" + reason, null);
            Recording = false;
            try { if (TickWriter != null) TickWriter.Flush(); if (EventWriter != null) EventWriter.Flush(); if (MarkerWriter != null) MarkerWriter.Flush(); } catch { }
            try { if (TickWriter != null) TickWriter.Dispose(); if (EventWriter != null) EventWriter.Dispose(); if (MarkerWriter != null) MarkerWriter.Dispose(); } catch { }
            TickWriter = null; EventWriter = null; MarkerWriter = null;
            try
            {
                File.WriteAllText(Path.Combine(SessionDir, "summary.txt"),
                    "Fire Pro Retail Flight Recorder build-gated candidate\r\n" +
                    "started_utc=" + _startedUtc.ToString("o") + "\r\n" +
                    "stopped_utc=" + DateTime.UtcNow.ToString("o") + "\r\n" +
                    "final_tick=" + Tick + "\r\n" +
                    "tick_rows=" + _tickRows + "\r\n" +
                    "event_rows=" + _eventRows + "\r\n" +
                    "markers=" + _markers + "\r\n" +
                    "reason=" + reason + "\r\n");
            } catch { }
            WriteStatus("STOPPED - capture saved: " + SessionDir);
        }

        void Mark()
        {
            if (!Recording) return;
            _markers++;
            MarkerWriter.WriteLine(Tsv(Tick, ++_eventSeq, DateTime.UtcNow.ToString("o"), "USER_F8"));
            MarkerWriter.Flush();
            WriteEvent("MARK", null, "USER_F8", null);
            WriteStatus("RECORDING - MARK " + _markers + " at tick " + Tick);
        }

        internal void WriteEvent(string phase, MethodBase method, object instance, object[] args)
        {
            if (!Recording || EventWriter == null) return;
            try
            {
                if (instance != null) Seen(instance);
                string methodName = method == null ? Convert.ToString(instance) : method.DeclaringType.Name + "." + method.Name;
                string inst = instance == null ? "" : instance.GetType().Name + "#" + RuntimeId(instance);
                string argText = "";
                if (args != null)
                {
                    var argTexts = new string[args.Length];
                    for (int i = 0; i < args.Length; i++) argTexts[i] = SafeBrief(args[i]);
                    argText = String.Join(" | ", argTexts);
                }
                EventWriter.WriteLine(Tsv(Tick, ++_eventSeq, phase, method == null ? "marker" : method.DeclaringType.Name, methodName, inst, argText,
                    R.Get(instance, "State", "mState", "state"), R.Get(instance, "NextState", "mNextState", "nextState"),
                    R.Get(instance, "currentFormIdx", "CurrentFormIdx", "FormIdx", "formIdx"),
                    R.Get(instance, "CurrentAnm", "currentAnm", "AnmNo", "anmNo", "AnimationNo"),
                    R.Get(instance, "CurrentBank", "currentBank", "BankNo", "bankNo", "AnmBank")));
                _eventRows++;
                if ((_eventRows & 63) == 0) EventWriter.Flush();
            }
            catch { }
        }

        void WriteTickRow(int slot, object p)
        {
            try
            {
                Seen(p);
                var pos = R.Vectorish(p, "PlPos", "plPos", "Pos", "mPlPos");
                var unity = R.UnityPosition(p);
                object animator = R.GetObject(p, "animator", "Animator", "mAnimator", "FormAnimator");
                object currentForm = R.GetObject(animator, "CurrentForm", "currentForm", "mCurrentForm", "Form") ?? R.GetObject(p, "CurrentForm", "currentForm");
                object skill = R.GetObject(p, "CurrentSkill", "currentSkill", "Waza", "WazaRequest", "Skill");
                TickWriter.WriteLine(Tsv(Tick, ++_eventSeq, slot, p.GetType().Name,
                    R.Get(p, "State", "mState", "state"), R.Get(p, "NextState", "mNextState", "nextState"),
                    pos.x, pos.y, pos.z, R.Get(p, "PlDir", "plDir", "Dir", "mPlDir"),
                    R.Get(p, "TargetPlIdx", "targetPlIdx", "TargetIdx", "targetIdx"), R.Get(p, "AnmHostPlayer", "anmHostPlayer", "AnmHostPlIdx"),
                    SafeBrief(skill),
                    R.Get(animator, "CurrentAnm", "currentAnm", "AnmNo", "anmNo", "AnimationNo"),
                    R.Get(animator, "CurrentBank", "currentBank", "BankNo", "bankNo", "AnmBank"),
                    R.Get(animator, "currentFormIdx", "CurrentFormIdx", "FormIdx", "formIdx"), R.Get(currentForm, "FormNo", "formNo", "No", "ID", "id"),
                    R.Get(animator, "FormDispDuration", "formDispDuration", "DispDuration", "mFormDispDuration"),
                    R.Get(currentForm, "RX", "rx"), R.Get(currentForm, "RY", "ry"), R.Get(currentForm, "FX", "fx"), R.Get(currentForm, "FZ", "fz"),
                    R.Get(currentForm, "FormRev", "formRev", "Rev", "rev", "flags", "Flag"),
                    R.Get(animator, "isAnmPause", "IsAnmPause", "mIsAnmPause"), R.Get(p, "isDownRequested", "IsDownRequested", "mIsDownRequested"),
                    R.Get(p, "DownTime", "downTime", "mDownTime"), R.Get(p, "HP", "hp", "mHP"), R.Get(p, "BP", "bp", "mBP"),
                    R.Get(p, "Spirit", "SP", "sp", "mSpirit"), R.Get(p, "WrsDP", "wrsDP", "mWrsDP"), R.Get(p, "LastDamage", "lastDamage", "mLastDamage"),
                    unity.x, unity.y, unity.z));
                _tickRows++;
                if ((_tickRows & 63) == 0) TickWriter.Flush();
            }
            catch { }
        }

        void WriteMetadata()
        {
            try
            {
                var playerType = AccessTools.TypeByName("Player");
                var asm = playerType == null ? null : playerType.Assembly;
                string loc = asm == null ? "" : asm.Location;
                File.WriteAllText(Path.Combine(SessionDir, "metadata.json"), "{\n" +
                    "  \"recorder_version\": \"build-gated-candidate\",\n" +
                    "  \"started_utc\": \"" + Esc(DateTime.UtcNow.ToString("o")) + "\",\n" +
                    "  \"unity_version\": \"" + Esc(Application.unityVersion) + "\",\n" +
                    "  \"product\": \"" + Esc(Application.productName) + "\",\n" +
                    "  \"game_version\": \"" + Esc(Application.version) + "\",\n" +
                    "  \"assembly_csharp\": \"" + Esc(loc) + "\",\n" +
                    "  \"assembly_csharp_sha256\": \"" + Esc(File.Exists(loc) ? Hash(loc) : "") + "\",\n" +
                    "  \"observational_only\": true\n" +
                    "}\n");
            } catch { }
        }

        internal void WriteStatus(string s)
        {
            try { File.WriteAllText(Path.Combine(Home, "recorder_status.txt"), s); } catch { }
        }

        static StreamWriter NewWriter(string p) { return new StreamWriter(new FileStream(p, FileMode.Create, FileAccess.Write, FileShare.Read), new UTF8Encoding(false), 1 << 16); }
        static string Signature(MethodBase m)
        {
            try
            {
                var ps = m.GetParameters();
                var names = new string[ps.Length];
                for (int i = 0; i < ps.Length; i++) names[i] = ps[i].ParameterType.Name;
                return "(" + String.Join(",", names) + ")";
            }
            catch { return ""; }
        }
        static string Hash(string p) { using (var s=File.OpenRead(p)) using (var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant(); }
        static string Esc(string s) { return (s ?? "").Replace("\\","\\\\").Replace("\"","\\\""); }
        static string RuntimeId(object o) { return o == null ? "" : System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(o).ToString(CultureInfo.InvariantCulture); }
        static string SafeBrief(object o)
        {
            if (o == null) return "";
            try
            {
                var t=o.GetType();
                if (t.IsPrimitive || o is string || o is decimal || t.IsEnum) return Convert.ToString(o, CultureInfo.InvariantCulture);
                var id=R.Get(o,"ID","Id","id","No","no","SkillID","SkillId","anmNo","AnmNo");
                var name=R.Get(o,"Name","name","SkillName","skillName");
                var x=(name!=""?name:t.Name) + (id!=""?"#"+id:"");
                return x.Replace("\t"," ").Replace("\r"," ").Replace("\n"," ");
            } catch { return "<?>"; }
        }
        static string Tsv(params object[] xs)
        {
            var vals = new string[xs.Length];
            for (int i = 0; i < xs.Length; i++) vals[i] = Clean(Convert.ToString(xs[i], CultureInfo.InvariantCulture));
            return String.Join("\t", vals);
        }
        static string Clean(string s) { return (s ?? "").Replace("\t"," ").Replace("\r"," ").Replace("\n"," "); }
    }

    public static class Hooks
    {
        public static void MatchPrefix(object __instance, MethodBase __originalMethod, object[] __args)
        {
            try { if (RecorderPlugin.I != null) { RecorderPlugin.I.BeginTick(); RecorderPlugin.I.WriteEvent("PRE", __originalMethod, __instance, __args); } } catch { }
        }
        public static void MatchPostfix(object __instance, MethodBase __originalMethod, object[] __args)
        {
            try { if (RecorderPlugin.I != null) { RecorderPlugin.I.WriteEvent("POST", __originalMethod, __instance, __args); RecorderPlugin.I.EndTick(); } } catch { }
        }
        public static void EventPrefix(object __instance, MethodBase __originalMethod, object[] __args)
        {
            try { if (RecorderPlugin.I != null) { RecorderPlugin.I.Seen(__instance); RecorderPlugin.I.WriteEvent("PRE", __originalMethod, __instance, __args); } } catch { }
        }
        public static void EventPostfix(object __instance, MethodBase __originalMethod, object[] __args)
        {
            try { if (RecorderPlugin.I != null) { RecorderPlugin.I.Seen(__instance); RecorderPlugin.I.WriteEvent("POST", __originalMethod, __instance, __args); } } catch { }
        }
    }

    internal static class R
    {
        static readonly BindingFlags BF = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        internal static string Get(object o, params string[] names)
        {
            var x=GetObject(o,names); if(x==null) return "";
            try { return Convert.ToString(x, CultureInfo.InvariantCulture); } catch { return ""; }
        }
        internal static object GetObject(object o, params string[] names)
        {
            if(o==null) return null;
            var t=o.GetType();
            foreach(var n in names)
            {
                try { var f=t.GetField(n,BF); if(f!=null) return f.GetValue(o); } catch { }
                try { var p=t.GetProperty(n,BF); if(p!=null && p.GetIndexParameters().Length==0) return p.GetValue(o,null); } catch { }
            }
            return null;
        }
        internal sealed class V3Text
        {
            internal string x, y, z;
            internal V3Text(string a, string b, string c) { x = a; y = b; z = c; }
        }
        internal static V3Text Vectorish(object o, params string[] names)
        {
            var v=GetObject(o,names); if(v==null) return new V3Text("","","");
            return new V3Text(Get(v,"x","X"),Get(v,"y","Y"),Get(v,"z","Z"));
        }
        internal static V3Text UnityPosition(object o)
        {
            try
            {
                var c = o as Component;
                if(c != null){ var p=c.transform.position; return new V3Text(p.x.ToString("R",CultureInfo.InvariantCulture),p.y.ToString("R",CultureInfo.InvariantCulture),p.z.ToString("R",CultureInfo.InvariantCulture)); }
                var tr=GetObject(o,"transform","Transform","mTransform") as Transform;
                if(tr!=null){ var p=tr.position; return new V3Text(p.x.ToString("R",CultureInfo.InvariantCulture),p.y.ToString("R",CultureInfo.InvariantCulture),p.z.ToString("R",CultureInfo.InvariantCulture)); }
                foreach(var f in o.GetType().GetFields(BF))
                {
                    if(typeof(Transform).IsAssignableFrom(f.FieldType)) { var x=f.GetValue(o) as Transform; if(x!=null){var p=x.position; return new V3Text(p.x.ToString("R",CultureInfo.InvariantCulture),p.y.ToString("R",CultureInfo.InvariantCulture),p.z.ToString("R",CultureInfo.InvariantCulture));} }
                    if(typeof(Component).IsAssignableFrom(f.FieldType)) { var c2=f.GetValue(o) as Component; if(c2!=null){var p=c2.transform.position; return new V3Text(p.x.ToString("R",CultureInfo.InvariantCulture),p.y.ToString("R",CultureInfo.InvariantCulture),p.z.ToString("R",CultureInfo.InvariantCulture));} }
                }
            } catch { }
            return new V3Text("","","");
        }
    }
}
