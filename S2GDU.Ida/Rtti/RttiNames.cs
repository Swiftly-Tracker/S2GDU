using S2GDU.Ida.Generated;

namespace S2GDU.Ida.Rtti;

public static unsafe class RttiNames
{
    private const uint MngNoDefInit = 0x8;

    private static readonly string[] VTablePrefixes = ["`vtable for'", "vtable for ", "`typeinfo for'", "typeinfo for "];

    public static string NormalizeVTableName(string name)
    {
        foreach (string prefix in VTablePrefixes)
        {
            if (name.Length > prefix.Length && name.StartsWith(prefix, StringComparison.Ordinal))
            {
                return name[prefix.Length..];
            }
        }

        return name;
    }

    public static string ExtractClassFromMangled(string m)
    {
        if (m.Length == 0)
        {
            return string.Empty;
        }

        if (m.StartsWith("??_7", StringComparison.Ordinal))
        {
            int end = m.IndexOf("@@6B@", StringComparison.Ordinal);
            string body = end > 4 ? m[4..end] : string.Empty;
            if (body.Length > 0 && body[0] != '?')
            {
                return body;
            }
        }

        int p = m.StartsWith("_ZTV", StringComparison.Ordinal) || m.StartsWith("_ZTI", StringComparison.Ordinal) || m.StartsWith("_ZTS", StringComparison.Ordinal) ? 4 : 0;

        if (TryLengthPrefixed(m, ref p, out string simple))
        {
            return simple;
        }

        if (p < m.Length && m[p] == 'N')
        {
            p++;
            var parts = new List<string>();
            while (p < m.Length && m[p] != 'E' && TryLengthPrefixed(m, ref p, out string part))
            {
                parts.Add(part);
            }

            if (parts.Count > 0)
            {
                return string.Join("::", parts);
            }
        }

        return Demangle(m);
    }

    private static bool TryLengthPrefixed(string m, ref int p, out string value)
    {
        value = string.Empty;
        int q = p;
        int len = 0;
        while (q < m.Length && char.IsAsciiDigit(m[q]) && len < 256)
        {
            len = len * 10 + (m[q] - '0');
            q++;
        }

        if (q == p || len <= 0 || len >= 256 || m.Length - q < len)
        {
            return false;
        }

        value = m.Substring(q, len);
        p = q + len;
        return true;
    }

    private static string Demangle(string m)
    {
        IdaKernel.AssertOwner();
        byte* name = Utf8.Allocate(m);
        QString q = default;
        try
        {
            if (IdaNative.demangle_name(&q, name, MngNoDefInit, 0) <= 0)
            {
                return string.Empty;
            }

            string s = q.Read().TrimEnd('\0');
            int pos = s.IndexOf("typeinfo for ", StringComparison.Ordinal);
            return pos >= 0 ? s[(pos + 13)..] : s;
        }
        finally
        {
            q.Dispose();
            Utf8.Free(name);
        }
    }
}
