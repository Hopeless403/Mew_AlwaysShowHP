/*
    

*/
using System;
using System.Runtime.InteropServices;

public sealed class PatchPlan
{
    public bool CanPatch;
    public nint Address;
    public nint Destination;
    public byte[] Bytes = Array.Empty<byte>();
    public string Reason = string.Empty;
}

public static class PatchPlanner
{
    public static PatchPlan PlanRelativeJumpPatchInRange(
        nint searchBase,
        int searchSize,
        string sourceSignature,
        int sourceInstructionOffset,
        byte[] expectedOriginalInstruction,
        string destinationSignature)
    {
        var plan = new PatchPlan();

        if (searchBase == nint.Zero || searchSize <= 0)
        {
            plan.Reason = "Invalid function search range.";
            return plan;
        }

        var sourceMatches = PePatternScanner.FindAllPatternsInRange(searchBase, searchSize, sourceSignature);
        if (sourceMatches.Count != 1)
        {
            plan.Reason = $"Source signature match count in function range was {sourceMatches.Count}, expected 1.";
            return plan;
        }

        var destMatches = PePatternScanner.FindAllPatternsInRange(searchBase, searchSize, destinationSignature);
        if (destMatches.Count != 1)
        {
            plan.Reason = $"Destination signature match count in function range was {destMatches.Count}, expected 1.";
            return plan;
        }

        nint patchAddr = sourceMatches[0] + sourceInstructionOffset;
        nint destAddr = destMatches[0];

        byte[] actual = new byte[expectedOriginalInstruction.Length];
        Marshal.Copy(patchAddr, actual, 0, actual.Length);

        for (int i = 0; i < expectedOriginalInstruction.Length; i++)
        {
            if (actual[i] != expectedOriginalInstruction[i])
            {
                plan.Reason =
                    $"Original bytes mismatch at patch site. " +
                    $"Expected {BitConverter.ToString(expectedOriginalInstruction)}, " +
                    $"got {BitConverter.ToString(actual)}.";
                return plan;
            }
        }

        if (expectedOriginalInstruction.Length < 5)
        {
            plan.Reason = "Instruction too short for rel32 JMP patch.";
            return plan;
        }

        long rel64 = destAddr - (patchAddr + 5);
        if (rel64 < int.MinValue || rel64 > int.MaxValue)
        {
            plan.Reason = "Destination is out of rel32 jump range.";
            return plan;
        }

        int rel32 = (int)rel64;

        byte[] patchBytes = new byte[expectedOriginalInstruction.Length];
        patchBytes[0] = 0xE9;
        BitConverter.GetBytes(rel32).CopyTo(patchBytes, 1);

        for (int i = 5; i < patchBytes.Length; i++)
            patchBytes[i] = 0x90;

        plan.CanPatch = true;
        plan.Address = patchAddr;
        plan.Destination = destAddr;
        plan.Bytes = patchBytes;
        plan.Reason = "Patch can be applied.";

        return plan;
    }
}