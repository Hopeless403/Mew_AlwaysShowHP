using MewgenicsModSdk;
using MewgenicsModSdk.Api;
using System.Runtime.InteropServices;

/// <summary>
/// Required exports for Framework
/// </summary>
internal static unsafe class Exports
{
    private static readonly AlwaysShowHP _mod = new();

    [UnmanagedCallersOnly(EntryPoint = "MewMod_GetInfo")]
    public static ModInfo* GetInfo() { try { return ModInfoHelper.GetInfo(_mod); } catch { return null; } }

    [UnmanagedCallersOnly(EntryPoint = "MewMod_Init")]
    public static void Init(MewgenicsApi* api) { try { _mod.InternalLoad(api); } catch { } }

    [UnmanagedCallersOnly(EntryPoint = "MewMod_Enable")]
    public static void Enable() { try { _mod.InternalEnable(); } catch { } }

    [UnmanagedCallersOnly(EntryPoint = "MewMod_Disable")]
    public static void Disable() { try { _mod.InternalDisable(); } catch { } }

    [UnmanagedCallersOnly(EntryPoint = "MewMod_ConfigReload")]
    public static void ConfigReload() { try { _mod.InternalConfigReload(); } catch { } }
}