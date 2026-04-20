using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

public static unsafe class PePatternScanner
{
    /// <summary>
    /// Matches byte signatures with wildcards. Returns all matches if there are multiple.
    /// </summary>
    public static List<nint> FindAllPatternsInRange(nint start, int size, string signature)
    {
        // Parse signature string as bytes
        string[] tokens = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        byte?[] pattern = new byte?[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            string token = tokens[i];
            pattern[i] = (token == "?" || token == "??")
                ? null
                : byte.Parse(token, System.Globalization.NumberStyles.HexNumber);
        }

        // Match pattern
        byte[] bytes = new byte[size];
        Marshal.Copy(start, bytes, 0, size);

        var results = new List<nint>();
        int lastStart = bytes.Length - pattern.Length;
        for (int i = 0; i <= lastStart; i++)
        {
            bool match = true;

            for (int j = 0; j < pattern.Length; j++)
            {
                if (pattern[j].HasValue && bytes[i + j] != pattern[j]!.Value)
                {
                    match = false;
                    break;
                }
            }

            if (match)
                results.Add(start + i);
        }

        return results;
    }

    /// <summary>
    /// Helper function to get .rdata and .text sections
    /// </summary>
    public static unsafe (nint Base, int Size) GetSection(ProcessModule module, string name)
    {
        byte* basePtr = (byte*)module.BaseAddress;

        int e_lfanew = *(int*)(basePtr + 0x3C);
        byte* nt = basePtr + e_lfanew;
        byte* fileHeader = nt + 4;
        ushort numberOfSections = *(ushort*)(fileHeader + 2);
        ushort sizeOfOptionalHeader = *(ushort*)(fileHeader + 16);
        byte* section = fileHeader + 20 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++)
        {
            byte* sec = section + (40 * i);

            Span<byte> nameBytes = stackalloc byte[8];
            for (int j = 0; j < 8; j++)
                nameBytes[j] = sec[j];

            string secName = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
            if (secName == name)
            {
                uint virtualSize = *(uint*)(sec + 8);
                uint virtualAddress = *(uint*)(sec + 12);
                return ((nint)(basePtr + virtualAddress), (int)virtualSize);
            }
        }

        return (nint.Zero, 0);
    }
}