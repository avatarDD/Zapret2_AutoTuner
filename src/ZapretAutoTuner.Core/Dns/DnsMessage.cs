using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace ZapretAutoTuner.Core.Dns;

/// <summary>Options of a query built by <see cref="DnsMessage.BuildQuery"/>.</summary>
public sealed class DnsQueryOptions
{
    public static readonly DnsQueryOptions Default = new();

    /// <summary>RD flag: ask for recursion.</summary>
    public bool RecursionDesired { get; init; } = true;

    /// <summary>Add an EDNS(0) OPT record.</summary>
    public bool UseEdns { get; init; } = true;

    /// <summary>Advertised UDP payload size; 1232 is the DNS Flag Day 2020 value that avoids IP fragmentation.</summary>
    public ushort UdpPayloadSize { get; init; } = 1232;

    /// <summary>Client Subnet option (needs <see cref="UseEdns"/>).</summary>
    public DnsClientSubnet? ClientSubnet { get; init; }
}

/// <summary>
/// A DNS message (RFC 1035 §4) — the wire codec used by the DNS probe: builds queries (with EDNS(0) and Client
/// Subnet) and parses responses with name compression. Parsing is strict about bounds: malformed input raises
/// <see cref="FormatException"/> (or <see cref="TryParse"/> returns false), never an index exception.
/// </summary>
public sealed class DnsMessage
{
    public const int HeaderLength = 12;

    /// <summary>Maximum encoded name length (RFC 1035 §2.3.4).</summary>
    public const int MaxNameLength = 255;

    /// <summary>Upper bound on compression pointers followed while reading one name (loop guard).</summary>
    public const int MaxPointerHops = 64;

    private const ushort FlagQr = 0x8000;
    private const ushort FlagAa = 0x0400;
    private const ushort FlagTc = 0x0200;
    private const ushort FlagRd = 0x0100;
    private const ushort FlagRa = 0x0080;
    private const ushort FlagAd = 0x0020;
    private const ushort FlagCd = 0x0010;

    public ushort Id { get; private init; }

    /// <summary>Raw flags word of the header.</summary>
    public ushort Flags { get; private init; }

    public bool IsResponse => (Flags & FlagQr) != 0;

    public int Opcode => (Flags >> 11) & 0xF;

    public bool IsAuthoritative => (Flags & FlagAa) != 0;

    public bool IsTruncated => (Flags & FlagTc) != 0;

    public bool RecursionDesired => (Flags & FlagRd) != 0;

    public bool RecursionAvailable => (Flags & FlagRa) != 0;

    public bool AuthenticData => (Flags & FlagAd) != 0;

    public bool CheckingDisabled => (Flags & FlagCd) != 0;

    /// <summary>RCODE, extended with the upper 8 bits from OPT when present.</summary>
    public DnsResponseCode ResponseCode { get; private init; }

    public IReadOnlyList<DnsQuestion> Questions { get; private init; } = [];

    public IReadOnlyList<DnsRecord> Answers { get; private init; } = [];

    public IReadOnlyList<DnsRecord> Authorities { get; private init; } = [];

    /// <summary>Additional records except OPT (see <see cref="Edns"/>).</summary>
    public IReadOnlyList<DnsRecord> Additionals { get; private init; } = [];

    public DnsEdns? Edns { get; private init; }

    /// <summary>
    /// Builds a query. <paramref name="name"/> must already be ASCII (IDN converted to punycode); a trailing dot is
    /// allowed. Throws <see cref="ArgumentException"/> for an invalid name.
    /// </summary>
    public static byte[] BuildQuery(ushort id, string name, DnsRecordType type, DnsQueryOptions? options = null)
    {
        options ??= DnsQueryOptions.Default;
        if (options.ClientSubnet is not null && !options.UseEdns)
            throw new ArgumentException("ECS требует EDNS(0)", nameof(options));
        var w = new ArrayBufferWriter<byte>(64);
        WriteU16(w, id);
        WriteU16(w, options.RecursionDesired ? FlagRd : (ushort)0);
        WriteU16(w, 1);
        WriteU16(w, 0);
        WriteU16(w, 0);
        WriteU16(w, options.UseEdns ? (ushort)1 : (ushort)0);
        w.Write(EncodeName(name));
        WriteU16(w, (ushort)type);
        WriteU16(w, 1); // IN
        if (options.UseEdns)
        {
            byte[] rdata = [];
            if (options.ClientSubnet is { } ecs)
            {
                var v = ecs.Encode();
                rdata = new byte[4 + v.Length];
                BinaryPrimitives.WriteUInt16BigEndian(rdata, DnsClientSubnet.OptionCode);
                BinaryPrimitives.WriteUInt16BigEndian(rdata.AsSpan(2), (ushort)v.Length);
                v.CopyTo(rdata, 4);
            }
            w.Write<byte>([0]); // root owner name
            WriteU16(w, (ushort)DnsRecordType.OPT);
            WriteU16(w, options.UdpPayloadSize);
            WriteU16(w, 0); // extended RCODE, version
            WriteU16(w, 0); // DO = 0, Z
            WriteU16(w, (ushort)rdata.Length);
            w.Write(rdata);
        }
        return w.WrittenSpan.ToArray();
    }

    /// <summary>Encodes a dotted ASCII name as a sequence of labels (no compression).</summary>
    public static byte[] EncodeName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.EndsWith('.'))
            name = name[..^1];
        if (name.Length == 0)
            return [0];
        var r = new List<byte>(name.Length + 2);
        foreach (var label in name.Split('.'))
        {
            if (label.Length == 0)
                throw new ArgumentException($"DNS: пустая метка в имени «{name}»", nameof(name));
            if (label.Length > 63)
                throw new ArgumentException($"DNS: метка длиннее 63 байт в имени «{name}»", nameof(name));
            r.Add((byte)label.Length);
            foreach (char c in label)
            {
                if (c is <= ' ' or > '~')
                    throw new ArgumentException($"DNS: имя «{name}» должно быть в ASCII (IDN — в punycode)", nameof(name));
                r.Add((byte)c);
            }
        }
        r.Add(0);
        if (r.Count > MaxNameLength)
            throw new ArgumentException($"DNS: имя «{name}» длиннее {MaxNameLength} байт", nameof(name));
        return [.. r];
    }

    /// <summary>Reads id and flags without parsing the rest (enough to spot TC=1 in a cut UDP response).</summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> message, out ushort id, out ushort flags)
    {
        if (message.Length < HeaderLength)
        {
            id = flags = 0;
            return false;
        }
        id = BinaryPrimitives.ReadUInt16BigEndian(message);
        flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        return true;
    }

    public static bool TryParse(ReadOnlySpan<byte> message, out DnsMessage? result)
    {
        try
        {
            result = Parse(message);
            return true;
        }
        catch (FormatException)
        {
            result = null;
            return false;
        }
    }

    /// <summary>Parses a message. Throws <see cref="FormatException"/> on malformed input.</summary>
    public static DnsMessage Parse(ReadOnlySpan<byte> message)
    {
        var r = new Reader(message);
        if (message.Length < HeaderLength)
            throw new FormatException("DNS: сообщение короче заголовка");
        ushort id = r.U16();
        ushort flags = r.U16();
        int qd = r.U16(), an = r.U16(), ns = r.U16(), ar = r.U16();
        var questions = new List<DnsQuestion>(Math.Min(qd, 4));
        for (int i = 0; i < qd; i++)
        {
            var qname = r.Name();
            var qtype = (DnsRecordType)r.U16();
            questions.Add(new DnsQuestion(qname, qtype, r.U16()));
        }
        var answers = ReadSection(ref r, an);
        var authorities = ReadSection(ref r, ns);
        var additionals = ReadSection(ref r, ar);

        DnsEdns? edns = null;
        int rcode = flags & 0xF;
        var opt = additionals.Where(x => x.Type == DnsRecordType.OPT).ToList();
        if (opt.Count > 1)
            throw new FormatException("DNS: больше одной записи OPT");
        if (opt.Count == 1)
        {
            var o = opt[0];
            rcode |= (int)(o.Ttl >> 24) << 4;
            edns = ParseEdns(o);
            additionals.Remove(o);
        }
        return new DnsMessage
        {
            Id = id,
            Flags = flags,
            ResponseCode = (DnsResponseCode)rcode,
            Questions = questions,
            Answers = answers,
            Authorities = authorities,
            Additionals = additionals,
            Edns = edns,
        };
    }

    /// <summary>
    /// Follows the CNAME chain for <paramref name="name"/> through the answer section and collects the A/AAAA
    /// addresses of the final name. A loop or a chain longer than 16 stops the walk at the last new name.
    /// </summary>
    public DnsChainResult ResolveChain(string name)
    {
        var chain = FollowCnames(name);
        var final = chain[^1];
        var addrs = new List<IPAddress>();
        foreach (var rec in Answers)
        {
            if (rec.Address is { } a && rec.Type is DnsRecordType.A or DnsRecordType.AAAA && NameEquals(rec.Name, final) && !addrs.Contains(a))
                addrs.Add(a);
        }
        return new DnsChainResult(final, chain, addrs);
    }

    /// <summary>Answer records of <paramref name="type"/> owned by the end of the CNAME chain that starts at <paramref name="name"/>.</summary>
    public IEnumerable<DnsRecord> AnswersFor(string name, DnsRecordType type)
    {
        var final = FollowCnames(name)[^1];
        return Answers.Where(x => x.Type == type && NameEquals(x.Name, final));
    }

    /// <summary>Case-insensitive DNS name comparison that ignores one trailing dot.</summary>
    public static bool NameEquals(string a, string b) =>
        string.Equals(a.TrimEnd('.'), b.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);

    private List<string> FollowCnames(string name)
    {
        var chain = new List<string> { name.TrimEnd('.') };
        for (int hop = 0; hop < 16; hop++)
        {
            var cur = chain[^1];
            var next = Answers.FirstOrDefault(x => x.Type == DnsRecordType.CNAME && NameEquals(x.Name, cur))?.Target;
            if (next is null || chain.Any(c => NameEquals(c, next)))
                break;
            chain.Add(next.TrimEnd('.'));
        }
        return chain;
    }

    private static List<DnsRecord> ReadSection(ref Reader r, int count)
    {
        var list = new List<DnsRecord>(Math.Min(count, 16));
        for (int i = 0; i < count; i++)
            list.Add(ReadRecord(ref r));
        return list;
    }

    private static DnsRecord ReadRecord(ref Reader r)
    {
        var name = r.Name();
        var type = (DnsRecordType)r.U16();
        ushort cls = r.U16();
        uint ttl = r.U32();
        int rdlen = r.U16();
        int start = r.Pos;
        var data = r.Bytes(rdlen);
        int end = r.Pos;
        IPAddress? addr = null;
        string? target = null;
        SvcbData? svcb = null;
        switch (type)
        {
            case DnsRecordType.A when cls == 1:
                if (rdlen != 4)
                    throw new FormatException("DNS: запись A не 4 байта");
                addr = new IPAddress(data);
                break;
            case DnsRecordType.AAAA when cls == 1:
                if (rdlen != 16)
                    throw new FormatException("DNS: запись AAAA не 16 байт");
                addr = new IPAddress(data);
                break;
            case DnsRecordType.CNAME or DnsRecordType.NS or DnsRecordType.PTR:
            {
                var sub = r.At(start);
                target = sub.Name();
                if (sub.Pos != end)
                    throw new FormatException($"DNS: имя в RDATA {type} не совпадает с RDLENGTH");
                break;
            }
            case DnsRecordType.SVCB or DnsRecordType.HTTPS:
            {
                if (rdlen < 3)
                    throw new FormatException("DNS: RDATA SVCB слишком короткая");
                var sub = r.At(start);
                ushort prio = sub.U16();
                var tn = sub.Name();
                if (sub.Pos > end)
                    throw new FormatException("DNS: имя цели SVCB выходит за RDATA");
                svcb = SvcbData.Create(prio, tn, r.Slice(sub.Pos, end - sub.Pos));
                break;
            }
        }
        return new DnsRecord { Name = name, Type = type, Class = cls, Ttl = ttl, Data = data.ToArray(), Address = addr, Target = target, Svcb = svcb };
    }

    private static DnsEdns ParseEdns(DnsRecord o)
    {
        var opts = new List<DnsEdnsOption>();
        DnsClientSubnet? ecs = null;
        var d = o.Data.AsSpan();
        for (int p = 0; p < d.Length;)
        {
            if (d.Length - p < 4)
                throw new FormatException("DNS: обрезанная опция EDNS");
            ushort code = BinaryPrimitives.ReadUInt16BigEndian(d[p..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(d[(p + 2)..]);
            p += 4;
            if (d.Length - p < len)
                throw new FormatException("DNS: опция EDNS выходит за RDATA");
            var v = d.Slice(p, len);
            p += len;
            opts.Add(new DnsEdnsOption(code, v.ToArray()));
            if (code == DnsClientSubnet.OptionCode)
                ecs = DnsClientSubnet.TryDecode(v);
        }
        return new DnsEdns
        {
            UdpPayloadSize = o.Class,
            Version = (byte)(o.Ttl >> 16),
            DnssecOk = (o.Ttl & 0x8000) != 0,
            Options = opts,
            ClientSubnet = ecs,
        };
    }

    private static void WriteU16(ArrayBufferWriter<byte> w, ushort v)
    {
        BinaryPrimitives.WriteUInt16BigEndian(w.GetSpan(2), v);
        w.Advance(2);
    }

    /// <summary>Bounds-checked big-endian reader over the whole message (names may point anywhere in it).</summary>
    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _m;

        public Reader(ReadOnlySpan<byte> m)
        {
            _m = m;
            Pos = 0;
        }

        public int Pos { get; private set; }

        public readonly Reader At(int pos) => new(_m) { Pos = pos };

        public readonly ReadOnlySpan<byte> Slice(int pos, int len) => _m.Slice(pos, len);

        public ushort U16()
        {
            Need(2);
            var v = BinaryPrimitives.ReadUInt16BigEndian(_m[Pos..]);
            Pos += 2;
            return v;
        }

        public uint U32()
        {
            Need(4);
            var v = BinaryPrimitives.ReadUInt32BigEndian(_m[Pos..]);
            Pos += 4;
            return v;
        }

        public ReadOnlySpan<byte> Bytes(int n)
        {
            Need(n);
            var s = _m.Slice(Pos, n);
            Pos += n;
            return s;
        }

        /// <summary>
        /// Reads a possibly compressed name (RFC 1035 §4.1.4). Pointers must land inside the message, at most
        /// <see cref="MaxPointerHops"/> are followed and the expanded name may not exceed 255 bytes.
        /// </summary>
        public string Name()
        {
            var sb = new StringBuilder();
            int p = Pos;
            int wire = 1;
            int hops = 0;
            bool jumped = false;
            while (true)
            {
                if (p >= _m.Length)
                    throw new FormatException("DNS: имя выходит за конец сообщения");
                int len = _m[p];
                if ((len & 0xC0) == 0xC0)
                {
                    if (p + 1 >= _m.Length)
                        throw new FormatException("DNS: обрезанный указатель сжатия");
                    int target = ((len & 0x3F) << 8) | _m[p + 1];
                    if (!jumped)
                    {
                        Pos = p + 2;
                        jumped = true;
                    }
                    if (++hops > MaxPointerHops)
                        throw new FormatException("DNS: цикл указателей сжатия");
                    if (target >= _m.Length)
                        throw new FormatException("DNS: указатель сжатия за пределами сообщения");
                    p = target;
                    continue;
                }
                if ((len & 0xC0) != 0)
                    throw new FormatException("DNS: неподдерживаемый тип метки");
                p++;
                if (len == 0)
                {
                    if (!jumped)
                        Pos = p;
                    break;
                }
                if (len > _m.Length - p)
                    throw new FormatException("DNS: метка выходит за конец сообщения");
                wire += len + 1;
                if (wire > MaxNameLength)
                    throw new FormatException("DNS: имя длиннее 255 байт");
                AppendLabel(sb, _m.Slice(p, len));
                sb.Append('.');
                p += len;
            }
            return sb.Length == 0 ? "." : sb.ToString(0, sb.Length - 1);
        }

        private readonly void Need(int n)
        {
            if (n < 0 || Pos > _m.Length - n)
                throw new FormatException("DNS: сообщение обрезано");
        }

        private static void AppendLabel(StringBuilder sb, ReadOnlySpan<byte> label)
        {
            foreach (byte b in label)
            {
                if (b is > (byte)' ' and <= (byte)'~' and not (byte)'.' and not (byte)'\\')
                    sb.Append((char)b);
                else
                    sb.Append('\\').Append(b.ToString("D3", CultureInfo.InvariantCulture));
            }
        }
    }
}
