using System.Runtime.InteropServices;
using S2GDU.Ida.Generated;

namespace S2GDU.Ida;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct TypeInfo : IDisposable
{
    public ulong Typid;

    public void Dispose()
    {
        fixed (TypeInfo* self = &this)
        {
            IdaNative.clear_tinfo_t(self);
        }

        Typid = 0;
    }
}
