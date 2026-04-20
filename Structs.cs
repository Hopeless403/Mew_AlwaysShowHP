using System.Collections.Generic;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct Vector<T> where T : unmanaged
{
    public T* first;
    public T* last;
    public T* end;
    public int Count
    {
        get
        {
            if (first == null || last == null)
                return 0;

            return (int)(last - first);
        }
    }

    public List<T> ToList()
    {
        int count = Count;
        var list = new List<T>(count);

        for (int i = 0; i < count; i++)
        {
            list.Add(first[i]);
        }

        return list;
    }
}
[StructLayout(LayoutKind.Sequential)]
public unsafe struct Array<T> where T : unmanaged
{
    public uint cap;
    public uint count;
    public T* items;

    public List<T> ToList()
    {
        var list = new List<T>((int)count);
        for (int i = 0; i < count; i++)
        {
            list.Add(items[i]);
        }

        return list;
    }
}
[StructLayout(LayoutKind.Sequential)]
public unsafe struct RefArray<T> where T : unmanaged
{
    public long refcount;
    public uint cap;
    public uint count;
    public T* items;

    public List<T> ToList()
    {
        var list = new List<T>((int)count);
        for (int i = 0; i < count; i++)
        {
            list.Add(items[i]);
        }

        return list;
    }
}