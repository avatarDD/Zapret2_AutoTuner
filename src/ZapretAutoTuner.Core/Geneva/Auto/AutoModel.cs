using System.Net;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Geneva.Auto;

/// <summary>
/// What a strategy of the "Авто" mode is found for and applied to (skill <c>geneva</c>, §9): a site by its name, a DNS
/// resolver, any other server by address and port, or a peer-to-peer program by its local port.
/// </summary>
public enum AutoKind
{
    /// <summary>TLS or HTTP over TCP to a site (its registrable domain).</summary>
    Web,

    /// <summary>QUIC to a site: browsers fall back to TCP, so it matters only when TCP fails too.</summary>
    Quic,

    /// <summary>A DNS resolver (port 53, UDP or TCP).</summary>
    Dns,

    /// <summary>Any other server: WireGuard, OpenVPN, DTLS, STUN, MTProto, an unknown protocol.</summary>
    Endpoint,

    /// <summary>A program that talks to many peers from one local port (DHT): applied by that port, not by address.</summary>
    LocalPort,
}

/// <summary>Where a service is in the "Авто" mode.</summary>
public enum AutoStatus
{
    /// <summary>Seen, nothing wrong.</summary>
    Watching,

    /// <summary>Its flows fail the way DPI makes them fail: the probe without a bypass decides.</summary>
    Suspected,

    /// <summary>The probe without a bypass failed too (the baseline, AGENTS.md rule 5): waits for its search.</summary>
    Blocked,

    /// <summary>The probe without a bypass passed: not blocked, watched again after a pause.</summary>
    NotBlocked,

    /// <summary>Not even a connection: the address is blocked, and no packet trick helps (a tunnel would).</summary>
    IpBlocked,

    /// <summary>QUIC fails, TCP to the same site works: the browser falls back, nothing to do.</summary>
    Fallback,

    /// <summary>Known strategies are tried, then geneva's search runs.</summary>
    Searching,

    /// <summary>A strategy works and is applied to the service's traffic only.</summary>
    Applied,

    /// <summary>Applied, and fails again: checked with the bypass on, then searched again.</summary>
    Degraded,

    /// <summary>No strategy worked; the search goes on later with more generations.</summary>
    NotFound,
}

/// <summary>
/// How much a service matters (issue 28): the order of confirmation and search, who may interrupt whose search, who
/// leaves a full book first. Lower is more important.
/// </summary>
public enum AutoPriority
{
    /// <summary>The user's list and the well-known services people wait for (YouTube, Discord, Telegram...).</summary>
    Important = 0,

    /// <summary>Sites and QUIC by name, DNS resolvers.</summary>
    Normal = 1,

    /// <summary>A server with a name or a known protocol (WireGuard, OpenVPN, STUN...).</summary>
    Low = 2,

    /// <summary>A bare address on a high port, DHT, peer-to-peer: never interrupts anyone and leaves a full book first.</summary>
    Background = 3,
}

/// <summary>The user's word about one service: it overrides the computed priority.</summary>
public enum AutoUserPriority
{
    None = 0,
    Important = 1,
    Unimportant = 2,
}

/// <summary>How one observed flow of a service went.</summary>
public enum AutoHealth
{
    Ok,

    /// <summary>Reset, hung, cut at 16 KB, no reply: what DPI does.</summary>
    Failed,

    /// <summary>The TCP handshake never completed.</summary>
    NoConnection,
}

/// <summary>One flow of the passive observation, attributed to its service.</summary>
public sealed record AutoSample
{
    public required string Key { get; init; }

    public required AutoKind Kind { get; init; }

    public required L4Kind Transport { get; init; }

    /// <summary>The name shown to the user: a domain, an address with its port, a protocol on a local port.</summary>
    public required string Name { get; init; }

    /// <summary>The full name the client asked for (SNI or the DNS answer), when known: the page the probe loads.</summary>
    public string? Host { get; init; }

    /// <summary>The protocol by its first packet: tls, http, quic, dns, wireguard, openvpn, dht, udp, tcp, ...</summary>
    public required string App { get; init; }

    public required IPEndPoint Server { get; init; }

    public int LocalPort { get; init; }

    public required DateTime Time { get; init; }

    public required AutoHealth Health { get; init; }

    /// <summary>Why the flow failed, in Russian (for the list); empty when it worked.</summary>
    public string Why { get; init; } = "";

    /// <summary>What the client sent before the server answered, when a replay of it can judge a strategy.</summary>
    public IReadOnlyList<byte[]> Replay { get; init; } = [];
}

/// <summary>The thresholds of the "Авто" mode, in one place so the docs and the tests name the same numbers.</summary>
public static class AutoRules
{
    /// <summary>The observation window: failures and successes older than this are forgotten.</summary>
    public static TimeSpan Window { get; } = TimeSpan.FromMinutes(10);

    /// <summary>Failed flows in the window (with no success) that make a service suspected.</summary>
    public const int FailsToSuspect = 3;

    /// <summary>UDP to one server: a client that retries is two failed flows already.</summary>
    public const int UdpFailsToSuspect = 2;

    /// <summary>DHT asks many peers, and dead peers are normal: only many questions and no answer at all count.</summary>
    public const int PeerFailsToSuspect = 20;

    /// <summary>
    /// An applied strategy is weakened when its failures in the window reach this many times
    /// <see cref="FailsToSuspect"/> (per transport) and are at least as many as its successes.
    /// </summary>
    public const int WeakFactor = 2;

    /// <summary>
    /// geneva's detector judges an applied strategy only after it held this long: a probe with the bypass that passed
    /// is not repeated at every mark of the same shaper.
    /// </summary>
    public static TimeSpan DetectorHold { get; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// An applied service in use within this time is checked with its bypass this often (the probe and the browser's
    /// handshakes, as the user's "Проверить сейчас").
    /// </summary>
    public static TimeSpan RoutineCheck { get; } = TimeSpan.FromMinutes(30);

    /// <summary>A service the probe found open is not suspected again before this.</summary>
    public static TimeSpan NotBlockedPause { get; } = TimeSpan.FromHours(1);

    /// <summary>An address block is looked at again after this (it may be lifted).</summary>
    public static TimeSpan IpBlockedPause { get; } = TimeSpan.FromHours(6);

    /// <summary>Probes in a row with no answer even with the bypass before a degraded service is taken for an address block.</summary>
    public const int TimeoutsToDrop = 3;

    /// <summary>When a degraded service whose server did not answer with the bypass is probed again.</summary>
    public static TimeSpan TimeoutRecheck { get; } = TimeSpan.FromMinutes(5);

    /// <summary>The first pause before a search that found nothing runs again; it doubles up to <see cref="MaxRetryPause"/>.</summary>
    public static TimeSpan RetryPause { get; } = TimeSpan.FromHours(1);

    public static TimeSpan MaxRetryPause { get; } = TimeSpan.FromHours(24);

    /// <summary>A service without a single flow for this long is dropped (unless its strategy is applied).</summary>
    public static TimeSpan Forget { get; } = TimeSpan.FromDays(30);

    /// <summary>An address of an applied service not seen for this long leaves its set.</summary>
    public static TimeSpan AddressLife { get; } = TimeSpan.FromDays(7);

    public const int MaxServices = 300;

    public const int MaxAddresses = 64;

    /// <summary>
    /// Strategies applied at once by default: one <c>geneva run</c> and one queue each (<see cref="GroupQueue"/>).
    /// The user may set any number (<c>GenevaState.AutoGroups</c>); each of the searches side by side needs a group of
    /// its own for its trials, so the working strategies must leave room.
    /// </summary>
    public const int DefaultMaxGroups = 16;

    /// <summary>
    /// The queue of the group in place <paramref name="i"/>: 340–347, then from 350 on (348 and 349 are the name-based
    /// process's and the detector's).
    /// </summary>
    public static int GroupQueue(int i) => i < 8 ? 340 + i : 350 + (i - 8);

    /// <summary>Known strategies tried on a blocked service before geneva's search.</summary>
    public const int MaxQuickCandidates = 12;

    /// <summary>Packets per connection that go through geneva: the handshake and the first data, not the download.</summary>
    public const int OutPackets = 12;

    public const int InPackets = 6;

    /// <summary>The search of the "Авто" mode: smaller than the manual one, continued later when it found nothing.</summary>
    public const int Population = 20;

    public const int Generations = 10;

    /// <summary>Generations added each time a search that found nothing is continued.</summary>
    public const int MoreGenerations = 5;

    /// <summary>
    /// Searches that found nothing in a row before the wider round: every known strategy and Geneva's library on the
    /// service's traffic, then a new, bigger search with more layers (<see cref="WidePopulation"/>).
    /// </summary>
    public const int WideAfter = 2;

    /// <summary>Strategies the wider round tries on the service's traffic before its search.</summary>
    public const int MaxWideCandidates = 40;

    public const int WidePopulation = 40;

    public const int WideGenerations = 15;

    /// <summary>The probes one search runs at once (geneva's workers): the user's choice, 1 by default.</summary>
    public const int MaxWorkers = GenevaArgv.MaxWorkers;

    /// <summary>
    /// Probes in a row a strategy must pass on the service before it is applied: one lucky load (a DPI that lets some
    /// connections through) is not a working bypass.
    /// </summary>
    public const int TrialPasses = 2;

    /// <summary>A waiting background service rises one level for each such wait (never above <see cref="AutoPriority.Low"/>).</summary>
    public static TimeSpan StarvationStep { get; } = TimeSpan.FromMinutes(30);

    /// <summary>Places of the book only important and normal services may take: peers cannot crowd them out.</summary>
    public const int ReservedPlaces = 60;

    /// <summary>Strategies applied by the site's name at once (geneva_c 2.0 profiles in one process).</summary>
    public const int MaxHostProfiles = 24;

    /// <summary>zapret2's fakes a wider round tries (<see cref="AutoCandidates.XFor"/>); the next round takes the next ones.</summary>
    public const int FakesPerRound = 8;

    /// <summary>The queue of the process that applies strategies by name: between the groups' 340–347 and 350 on.</summary>
    public const int HostQueue = 348;

    /// <summary>Ports whose connections the name-based process sees (TLS and HTTP; QUIC over UDP 443).</summary>
    public const string HostTcpPorts = "80,443";

    public const string HostUdpPorts = "443";

    /// <summary>
    /// The queue of geneva's detector (<c>run --ext --ext-auto observe</c>, geneva_c 2.0 with <c>ext_auto</c>): it
    /// changes no traffic, its engine takes only <see cref="ObservePort"/>, and its NFLOG group has the same number.
    /// </summary>
    public const int ObserveQueue = 349;

    /// <summary>The port the detector's engine nominally takes (discard): nothing real goes through its queue.</summary>
    public const string ObservePort = "9";

    /// <summary>The detector's classes the program's own observation cannot see in a 15 s slice: a shaper and a freeze.</summary>
    public static IReadOnlySet<string> DetectorClasses { get; } = new HashSet<string>(StringComparer.Ordinal) { "THROTTLE", "FREEZE_N" };
}
