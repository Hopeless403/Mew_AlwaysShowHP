using System;
using System.Runtime.InteropServices;

/// <summary>
/// Utility to patch bytes at runtime. 
/// Framework's PatchHelper was considered but there's no easy way to restore a specific patch.
/// </summary>
public static unsafe class RuntimePatch
{
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(
        nint lpAddress,
        nuint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(
        nint hProcess,
        nint lpBaseAddress,
        nuint dwSize);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    public sealed class PatchHandle
    {
        public nint Address;
        public byte[] OriginalBytes = Array.Empty<byte>();
        public bool Applied;
    }


    public static PatchHandle PatchRet(nint functionPtr)
    {
        var handle = new PatchHandle
        {
            Address = functionPtr,
            OriginalBytes = new byte[1]
        };

        Marshal.Copy(functionPtr, handle.OriginalBytes, 0, 1);

        byte* bytes = stackalloc byte[] { 0xC3 };
        WriteBytes(functionPtr, bytes, 1);
        handle.Applied = true;
        return handle;
    }

    public static PatchHandle PatchBytes(nint address, ReadOnlySpan<byte> newBytes)
    {
        var handle = new PatchHandle
        {
            Address = address,
            OriginalBytes = new byte[newBytes.Length]
        };

        Marshal.Copy(address, handle.OriginalBytes, 0, newBytes.Length);

        fixed (byte* pNew = newBytes)
        {
            WriteBytes(address, pNew, newBytes.Length);
        }

        handle.Applied = true;
        return handle;
    }

    public static void Restore(PatchHandle handle)
    {
        if (!handle.Applied)
            return;

        fixed (byte* pOld = handle.OriginalBytes)
        {
            WriteBytes(handle.Address, pOld, handle.OriginalBytes.Length);
        }

        handle.Applied = false;
    }

    private static void WriteBytes(nint address, byte* src, int length)
    {
        if (!VirtualProtect(address, (nuint)length, PAGE_EXECUTE_READWRITE, out uint oldProtect))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        Buffer.MemoryCopy(src, (void*)address, length, length);

        if (!FlushInstructionCache(GetCurrentProcess(), address, (nuint)length))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        if (!VirtualProtect(address, (nuint)length, oldProtect, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
}