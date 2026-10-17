using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Tls;

namespace ZapretAutoTuner.Probes.Tests;

public class HelloProbeTests
{
    private static HelloProbeOptions Opts(TestServer s, string spec = "chrome141", bool kyber = true) => new()
    {
        Address = IPAddress.Loopback,
        Port = s.Port,
        Spec = ClientHelloSpec.Get(spec),
        Hello = new ClientHelloOptions { Sni = "blocked.test", Kyber = kyber },
        ReplyTimeout = TimeSpan.FromSeconds(2),
    };

    [Theory]
    [InlineData("chrome141")]
    [InlineData("chrome_legacy")]
    [InlineData("firefox")]
    [InlineData("safari")]
    [InlineData("tv_tls12")]
    public async Task Real_tls_server_answers_every_client_shape(string spec)
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf("blocked.test"));
        var r = await HelloProbe.RunAsync(Opts(s, spec));
        Assert.True(r.PassedDpi, r.ToString());
        Assert.Contains(r.Outcome, new[] { HelloOutcome.ServerHello, HelloOutcome.HelloRetryRequest });
        Assert.Equal(spec == "tv_tls12" ? 0x0303 : 0x0304, r.ServerVersion);
        Assert.Equal("blocked.test", s.LastSni);
        Assert.NotNull(r.Ja4);
    }

    [Theory]
    [InlineData(ServerMode.ResetOnHello, HelloOutcome.Reset)]
    [InlineData(ServerMode.SilentOnHello, HelloOutcome.Timeout)]
    [InlineData(ServerMode.CloseOnHello, HelloOutcome.Closed)]
    public async Task Blocks_are_told_apart(ServerMode mode, HelloOutcome expected)
    {
        await using var s = new TestServer(mode);
        var r = await HelloProbe.RunAsync(Opts(s));
        Assert.Equal(expected, r.Outcome);
        Assert.False(r.PassedDpi);
        Assert.True(r.HelloBytes > 1400); // kyber hello
    }

    [Fact]
    public async Task Plain_http_server_is_not_tls()
    {
        await using var s = new TestServer(ServerMode.Ok, cert: null, bodyBytes: 10);
        // the plain server waits for \r\n\r\n; a TLS hello never has it, so it stays silent
        var r = await HelloProbe.RunAsync(Opts(s) with { ReplyTimeout = TimeSpan.FromMilliseconds(500) });
        Assert.Equal(HelloOutcome.Timeout, r.Outcome);
    }

    [Fact]
    public void Judge_reads_alert_hrr_and_partial_records()
    {
        Assert.Equal((HelloOutcome.Alert, 40, (int?)null, (int?)null), HelloProbe.Judge([0x15, 3, 3, 0, 2, 2, 40], false));
        Assert.Equal(HelloOutcome.Timeout, HelloProbe.Judge([0x16, 3, 3], false).Item1);
        Assert.Equal(HelloOutcome.NotTls, HelloProbe.Judge("HTTP/1.1 403"u8, false).Item1);

        var hrr = new List<byte> { 0x16, 3, 3, 0, 0, 2, 0, 0, 0, 3, 3 };
        hrr.AddRange(Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"));
        hrr.Add(0); // session id
        hrr.AddRange([0x13, 0x01, 0]); // cipher, compression
        hrr.AddRange([0, 6, 0, 0x2B, 0, 2, 3, 4]); // supported_versions = 1.3
        int len = hrr.Count - 5;
        hrr[3] = (byte)(len >> 8);
        hrr[4] = (byte)len;
        var j = HelloProbe.Judge(hrr.ToArray(), false);
        Assert.Equal(HelloOutcome.HelloRetryRequest, j.Item1);
        Assert.Equal(0x0304, j.Item3);
        Assert.Equal(0x1301, j.Item4);
        // cut after the random: still a server answer when the flow ended there
        Assert.Equal(HelloOutcome.HelloRetryRequest, HelloProbe.Judge(hrr.Take(45).ToArray(), true).Item1);
    }
}
