using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Sequential)]
public struct CompleteObjectLocator64
{
    public uint signature;
    public uint offset;
    public uint cdOffset;
    public uint pTypeDescriptor;
    public uint pClassHierarchyDescriptor;
    public uint pSelf;
}

public static class RttiScanner
{
    /// <summary>
    /// Scans within the game module for the vftable corresponding to mangledNames e.g. ".?AVStatusMenu@glaiel@@". 
    /// TODO: Might be useful to cache the intermediate tables if that's needed.
    /// </summary>
    public static nint FindVftableByRttiName(ProcessModule module, string mangledName)
    {
        var (rdataBase, rdataSize) = PePatternScanner.GetSection(module, ".rdata");
        var (textBase, textSize) = PePatternScanner.GetSection(module, ".text");

        if (rdataBase == nint.Zero || rdataSize == 0)
            return nint.Zero;

        int ptrSize = IntPtr.Size;

        for (int i = 0; i <= rdataSize - ptrSize * 4; i += ptrSize)
        {
            nint metaPtr = rdataBase + i;
            nint colPtr = Marshal.ReadIntPtr(metaPtr);

            if (!IsInModule(module, colPtr))
                continue;

            if (!TryReadCol(module, colPtr, out var col))
                continue;

            if (col.signature > 1)
                continue;

            if (!IsValidRva(module, col.pTypeDescriptor))
                continue;

            nint typeDesc = module.BaseAddress + (int)col.pTypeDescriptor;
            nint nameAddr = typeDesc + 0x10;

            string? actualName = ReadAsciiString(nameAddr, 256);
            if (!string.Equals(actualName, mangledName, StringComparison.Ordinal))
                continue;

            // strong sanity check: first few vftable slots should point into .text
            nint vftable = metaPtr + ptrSize;
            nint fn0 = Marshal.ReadIntPtr(vftable + 0 * ptrSize);
            nint fn1 = Marshal.ReadIntPtr(vftable + 1 * ptrSize);
            nint fn2 = Marshal.ReadIntPtr(vftable + 2 * ptrSize);

            if (!IsInRange(fn0, textBase, textSize) ||
                !IsInRange(fn1, textBase, textSize) ||
                !IsInRange(fn2, textBase, textSize))
            {
                continue;
            }

            return vftable;
        }

        return nint.Zero;
    }

    public static nint GetVirtualAtSlot(nint vftable, int slot)
    {
        if (vftable == nint.Zero)
            return nint.Zero;

        return Marshal.ReadIntPtr(vftable + slot * IntPtr.Size);
    }

    private static bool TryReadCol(ProcessModule module, nint colPtr, out CompleteObjectLocator64 col)
    {
        col = default;

        if (!IsInModule(module, colPtr))
            return false;

        try
        {
            col = Marshal.PtrToStructure<CompleteObjectLocator64>(colPtr);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsValidRva(ProcessModule module, uint rva)
    {
        return rva != 0 && rva < module.ModuleMemorySize;
    }

    private static bool IsInModule(ProcessModule module, nint ptr)
    {
        return ptr >= module.BaseAddress && ptr < module.BaseAddress + module.ModuleMemorySize;
    }

    private static bool IsInRange(nint ptr, nint baseAddr, int size)
    {
        return ptr >= baseAddr && ptr < baseAddr + size;
    }

    private static unsafe string? ReadAsciiString(nint address, int maxLen)
    {
        byte* p = (byte*)address;
        var bytes = new byte[maxLen];
        int len = 0;

        for (; len < maxLen; len++)
        {
            byte b = p[len];
            if (b == 0)
                break;

            if (b < 0x20 || b > 0x7E)
                return null;

            bytes[len] = b;
        }

        return len == 0 ? null : Encoding.ASCII.GetString(bytes, 0, len);
    }
}