#define DEBUG

using MewgenicsModSdk;
using MewgenicsModSdk.Api;
using MewgenicsModSdk.Game;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

// dotnet publish -c Release -r win-x64
public partial class AlwaysShowHP : MewgenicsMod
{
#if DEBUG
    [DllImport("kernel32.dll")]
    static extern bool AllocConsole();
#endif

    internal static AlwaysShowHP? instance;

    public override string Id => "AlwaysShowHP";
    public override string Name => "Always Show HP";
    public override string Version => "1.0.0";
    public override string Description => "Does something cool.";
    public override string Category => "Quality of Life";
    public override bool AutoEnable => true;
    public void Log(object message)
    {
        base.Log($"[{Name}]\t{message.ToString()}");
        Console.WriteLine(message);
    }

    static ulong pStatusMenu_lateUpdate;
    static PatchPlan StatusMenu_plan;
    static HookSlot StatusMenu_hook;

    public override unsafe void OnLoad(MewgenicsApi* api)
    {
        instance = this;
#if DEBUG
        //_debugLogHook = Hook(0x94F0B0, &DebugLogPopHook);
        AllocConsole();
        //_originalLog = api->Log;
        //api->Log = &LogHook;
#endif
        base.OnLoad(api);

        var module = Process.GetCurrentProcess().MainModule!;
        nint vftable = RttiScanner.FindVftableByRttiName(module, ".?AVStatusMenu@glaiel@@");

        if (vftable != nint.Zero)
        {
            Log($"StatusMenu vftable = 0x{vftable - module.BaseAddress:X}");

            var func = RttiScanner.GetVirtualAtSlot(vftable, 11);
            pStatusMenu_lateUpdate = (ulong)(func - module.BaseAddress);
            Log($"slot[11] (late_update) RVA = 0x{pStatusMenu_lateUpdate:X}");

            // After floating icons are rendered, decide whether we can jump to the end of the function.
            // Floaters = hp, shield, divine shield, corpse health
            StatusMenu_plan = PatchPlanner.PlanRelativeJumpPatchInRange(
                func + 0x1500,
                0x4000,
                "44 0F 10 7D 70 F2 44 0F 10 B5 F0 00 00 00 0F B6 9D 58 05 00 00", // signature near floaters
                14,
                [0x0F, 0xB6, 0x9D, 0x58, 0x05, 0x00, 0x00], // specific instruction to patch
                "4C 8D 9C 24 10 06 00 00 49 8B 5B 40 41 0F 28 73 F0 41 0F 28 7B E0 45 0F 28 43 D0" // signature near return
            );

            instance.Log(StatusMenu_plan.Reason);

            if (StatusMenu_plan.CanPatch)
            {
                instance.Log($"Patch address: 0x{StatusMenu_plan.Address - SharedGameBase:X}");
                instance.Log($"Destination : 0x{StatusMenu_plan.Destination - SharedGameBase:X}");
                instance.Log($"Patch bytes : {BitConverter.ToString(StatusMenu_plan.Bytes)}");

                StatusMenu_hook =
                    Hook(pStatusMenu_lateUpdate, (nint)(delegate* unmanaged<nint, void>)&StatusMenuLateUpdate);
            }
        }
        else
        {
            Log("Failed to find StatusMenu vftable");
        }
        Log("Installing hooks?");

#if DEBUG
        GameEvents.OnStevenSpawn += e => e.Cancel();
#endif

        Log("Hooks successfully installed");
    }

    [UnmanagedCallersOnly]
    private unsafe static void StatusMenuLateUpdate(nint a)
    {
        var plan = StatusMenu_plan;
        if (instance.IsEnabled && (plan?.CanPatch ?? false))
        {
            List<FightChar> arr = (Fight.Current?.GetFighters() ?? []).ToList();
            if (arr.Count == 0)
            {
                var battleScene = Memory.ReadPtr(a, 0x20); 
                var getComponents = Memory.Read<nint>(battleScene, 0x20);
                var cache = Memory.ReadPtr(getComponents + 0x10 * 503); 
                // 503 = Character. TODO fix if this changes ;-;
                var cs = Memory.Read<Array<nint>>(cache, 0x8).ToList();

                foreach (var c in cs)
                {
                    var character = new FightChar(c);
                    if (character.IsRealCombatant) arr.Add(character);
                }
            }
            if (arr.Count > 0)
            {
                nint addr = plan.Address;
                var patch = RuntimePatch.PatchBytes(addr, plan.Bytes/*
                [
                    0xE9, 0xDD, 0x18, 0x00, 0x00, // jmp 1408193DC
                    0x90, 0x90                    // pad to 7 bytes
                ]*/);

                var original = Memory.Read<FightChar>(a, 0xf0);

                try
                {
                    foreach (var f in arr)
                    {
                        Memory.Write(a, 0xf0, f);
                        StatusMenu_hook.Invoke(a);
                    }
                }
                finally
                {
                    Memory.Write(a, 0xf0, original);
                    RuntimePatch.Restore(patch);
                }
            }
        }

        StatusMenu_hook.Invoke(a);
    }

    //[UnmanagedCallersOnly]
    //private unsafe static nint TargetHpUI(nint a, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7)
    //{
    //    Memory.Write<double>(a7, 2);
    //    Memory.Write<double>(a7 + 0x8, 2);
    //    Memory.Write<double>(a7 + 0x10, 2);

    //    nint ret = InvokeRet(_hooks[0x33cd50], a, a2, a3, a4, a5, a6, a7);

    //    return ret;
    //}

    protected override void OnLoad()
    {
    }
    protected unsafe override void OnEnable()
    {

    }
    protected override void OnDisable() => Log("disabled");


    public static unsafe nint InvokeRet(HookSlot hook, nint a, nint b, nint c, nint d, nint e, nint f, nint g)
        => ((delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint>)hook.Trampoline)(a, b, c, d, e, f, g);
}