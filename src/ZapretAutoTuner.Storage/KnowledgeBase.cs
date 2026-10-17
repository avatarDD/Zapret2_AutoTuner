using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Storage;

/// <summary>Where results were measured: the provider, not the address (P2P shares by ASN).</summary>
public sealed record NetworkInfo(int? Asn, string? Isp, string? Country = null, string? Label = null);

public sealed record StoredResult
{
    public required string StrategyHash { get; init; }

    public required string Args { get; init; }

    public string? Family { get; init; }

    public required string Host { get; init; }

    public string ClientProfile { get; init; } = "default";

    public Efficiency Efficiency { get; init; }

    public string Status { get; init; } = "failed";

    public double? Score { get; init; }

    public string? BlockLabel { get; init; }

    public int? Asn { get; init; }

    public string Origin { get; init; } = "local";

    public DateTimeOffset Updated { get; init; }
}

public sealed record SessionInfo(long Id, string Uid, string Host, string Mode, string State, string? BlockLabel, string? Checkpoint, DateTimeOffset Started, DateTimeOffset Updated);

public sealed record TrialRecord
{
    public required Strategy Strategy { get; init; }

    public string? Family { get; init; }

    public required string Host { get; init; }

    public int Port { get; init; } = 443;

    public string L4 { get; init; } = "tcp";

    public string ClientProfile { get; init; } = "default";

    public string Level { get; init; } = "L2";

    public bool Ok { get; init; }

    public string? Error { get; init; }

    public long BytesIn { get; init; }

    public TimeSpan Duration { get; init; }

    public long? SessionId { get; init; }

    public long? NetworkId { get; init; }

    public string? BlockLabel { get; init; }
}

/// <summary>
/// The local SQLite knowledge base: settings, measured networks, strategies, every trial and the per-target results,
/// search sessions (resume after a restart), refinement history and checker runs. One file in the data dir; nothing
/// leaves the machine (no telemetry, AGENTS.md rule 7).
/// </summary>
public sealed class KnowledgeBase : IDisposable
{
    private readonly SqliteConnection _db;
    private readonly Lock _gate = new();

    private KnowledgeBase(SqliteConnection db)
    {
        _db = db;
    }

    public string Path { get; private init; } = "";

    public static KnowledgeBase Open(string path)
    {
        var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
        if (dir is not null)
            Directory.CreateDirectory(dir);
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        db.Open();
        var kb = new KnowledgeBase(db) { Path = path };
        kb.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
        kb.Migrate();
        return kb;
    }

    /// <summary>An in-memory base for tests.</summary>
    public static KnowledgeBase OpenInMemory()
    {
        var db = new SqliteConnection("Data Source=:memory:");
        db.Open();
        var kb = new KnowledgeBase(db) { Path = ":memory:" };
        kb.Exec("PRAGMA foreign_keys=ON;");
        kb.Migrate();
        return kb;
    }

    public int SchemaVersion => (int)(long)Scalar("PRAGMA user_version")!;

    private void Migrate()
    {
        int current = SchemaVersion;
        foreach (var (version, sql) in Schema.Migrations.Where(m => m.Version > current).OrderBy(m => m.Version))
        {
            using var tx = _db.BeginTransaction();
            Exec(sql, tx: tx);
            Exec($"PRAGMA user_version = {version}", tx: tx);
            tx.Commit();
        }
        if (SchemaVersion > Schema.Version)
            throw new InvalidOperationException($"база знаний новее программы (схема {SchemaVersion}, программа знает {Schema.Version})");
    }

    // ---- settings ----

    public string? GetSetting(string key) => (string?)Scalar("SELECT value FROM settings WHERE key=$k", ("$k", key));

    public void SetSetting(string key, string value) =>
        Exec("INSERT INTO settings(key,value,updated_at) VALUES($k,$v,$t) ON CONFLICT(key) DO UPDATE SET value=$v, updated_at=$t",
            ("$k", key), ("$v", value), ("$t", Now()));

    public void RemoveSetting(string key) => Exec("DELETE FROM settings WHERE key=$k", ("$k", key));

    public IReadOnlyDictionary<string, string> AllSettings()
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in Rows("SELECT key, value FROM settings"))
            d[(string)r[0]!] = (string)r[1]!;
        return d;
    }

    // ---- networks, strategies, targets ----

    /// <summary>The network row for this ASN and provider, created on first sight.</summary>
    public long Network(NetworkInfo n)
    {
        lock (_gate)
        {
            var id = Scalar("SELECT id FROM networks WHERE asn IS $a AND isp IS $i", ("$a", n.Asn), ("$i", n.Isp));
            if (id is long existing)
            {
                Exec("UPDATE networks SET last_seen=$t, country=COALESCE($c,country), label=COALESCE($l,label) WHERE id=$id",
                    ("$t", Now()), ("$c", n.Country), ("$l", n.Label), ("$id", existing));
                return existing;
            }
            return (long)Scalar("INSERT INTO networks(uid,asn,isp,country,label,first_seen,last_seen) VALUES($u,$a,$i,$c,$l,$t,$t) RETURNING id",
                ("$u", Guid.NewGuid().ToString("N")), ("$a", n.Asn), ("$i", n.Isp), ("$c", n.Country), ("$l", n.Label), ("$t", Now()))!;
        }
    }

    /// <summary>Canonical key of a strategy: sha256 of its argument text, the same on every machine.</summary>
    public static string HashOf(Strategy s) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s.ToString())));

    public long StrategyId(Strategy s, string? family = null, string l4 = "tcp", string origin = "local")
    {
        lock (_gate)
        {
            var hash = HashOf(s);
            if (Scalar("SELECT id FROM strategies WHERE hash=$h", ("$h", hash)) is long id)
                return id;
            return (long)Scalar("INSERT INTO strategies(hash,args,family,l4,instances,created_at,origin) VALUES($h,$a,$f,$l,$n,$t,$o) RETURNING id",
                ("$h", hash), ("$a", s.ToString()), ("$f", family), ("$l", l4), ("$n", s.InstanceCount), ("$t", Now()), ("$o", origin))!;
        }
    }

    public long TargetId(string host, int port = 443, string l4 = "tcp")
    {
        lock (_gate)
        {
            host = host.ToLowerInvariant();
            if (Scalar("SELECT id FROM targets WHERE host=$h AND port=$p AND l4=$l", ("$h", host), ("$p", port), ("$l", l4)) is long id)
                return id;
            return (long)Scalar("INSERT INTO targets(host,port,l4) VALUES($h,$p,$l) RETURNING id", ("$h", host), ("$p", port), ("$l", l4))!;
        }
    }

    // ---- trials and results ----

    /// <summary>Stores one attempt and folds it into the result row; returns the updated efficiency.</summary>
    public Efficiency RecordTrial(TrialRecord t)
    {
        lock (_gate)
        {
            long sid = StrategyId(t.Strategy, t.Family, t.L4);
            long tid = TargetId(t.Host, t.Port, t.L4);
            using var tx = _db.BeginTransaction();
            Exec("""
                INSERT INTO trials(uid,session_id,strategy_id,target_id,network_id,client_profile,level,ok,error,bytes_in,duration_ms,created_at)
                VALUES($u,$s,$st,$tg,$n,$c,$lv,$ok,$e,$b,$d,$t)
                """, tx,
                ("$u", Guid.NewGuid().ToString("N")), ("$s", t.SessionId), ("$st", sid), ("$tg", tid), ("$n", t.NetworkId), ("$c", t.ClientProfile),
                ("$lv", t.Level), ("$ok", t.Ok ? 1 : 0), ("$e", t.Error), ("$b", t.BytesIn), ("$d", (long)t.Duration.TotalMilliseconds), ("$t", Now()));
            Exec("""
                INSERT INTO results(uid,strategy_id,target_id,network_id,client_profile,successes,attempts,status,block_label,updated_at)
                VALUES($u,$st,$tg,$n,$c,$ok,1,'failed',$bl,$t)
                ON CONFLICT(strategy_id,target_id,network_id,client_profile,origin) DO UPDATE SET
                    successes = successes + $ok, attempts = attempts + 1, updated_at = $t, block_label = COALESCE($bl, block_label)
                """, tx,
                ("$u", Guid.NewGuid().ToString("N")), ("$st", sid), ("$tg", tid), ("$n", t.NetworkId ?? 0), ("$c", t.ClientProfile),
                ("$ok", t.Ok ? 1 : 0), ("$bl", t.BlockLabel), ("$t", Now()));
            var row = Rows("SELECT successes, attempts FROM results WHERE strategy_id=$st AND target_id=$tg AND network_id=$n AND client_profile=$c AND origin='local'", tx,
                ("$st", sid), ("$tg", tid), ("$n", t.NetworkId ?? 0), ("$c", t.ClientProfile)).Single();
            var eff = new Efficiency((int)(long)row[0]!, (int)(long)row[1]!);
            Exec("UPDATE results SET status=$s WHERE strategy_id=$st AND target_id=$tg AND network_id=$n AND client_profile=$c AND origin='local'", tx,
                ("$s", StatusOf(eff)), ("$st", sid), ("$tg", tid), ("$n", t.NetworkId ?? 0), ("$c", t.ClientProfile));
            tx.Commit();
            return eff;
        }
    }

    public void SetScore(Strategy s, string host, double score, long? networkId = null, string clientProfile = "default")
    {
        lock (_gate)
        {
            Exec("""
                UPDATE results SET score=$sc WHERE origin='local' AND client_profile=$c AND network_id=$n
                  AND strategy_id=(SELECT id FROM strategies WHERE hash=$h) AND target_id IN (SELECT id FROM targets WHERE host=$host)
                """, ("$sc", score), ("$c", clientProfile), ("$n", networkId ?? 0), ("$h", HashOf(s)), ("$host", host.ToLowerInvariant()));
        }
    }

    public static string StatusOf(Efficiency e) => e.Working ? "working" : e.Successes > 0 ? "partial" : "failed";

    /// <summary>Results for a host, best first (working, then by rate and score).</summary>
    public List<StoredResult> Results(string host, long? networkId = null)
    {
        lock (_gate)
        {
            var sql = """
                SELECT s.hash, s.args, s.family, t.host, r.client_profile, r.successes, r.attempts, r.status, r.score, r.block_label, n.asn, r.origin, r.updated_at
                FROM results r JOIN strategies s ON s.id=r.strategy_id JOIN targets t ON t.id=r.target_id LEFT JOIN networks n ON n.id=r.network_id
                WHERE t.host=$h AND ($n IS NULL OR r.network_id=$n)
                ORDER BY r.status='working' DESC, CAST(r.successes AS REAL)/MAX(r.attempts,1) DESC, COALESCE(r.score, 1e9), r.attempts DESC
                """;
            return Rows(sql, null, ("$h", host.ToLowerInvariant()), ("$n", networkId)).Select(ToResult).ToList();
        }
    }

    /// <summary>
    /// Strategies that worked for other targets on the same provider (dpi-diagnostics §6.2 "adaptive search"): the
    /// search tries them first. Ordered by how many targets they opened.
    /// </summary>
    public List<(Strategy Strategy, string? Family, int Targets)> WorkedOnNetwork(int? asn, string l4 = "tcp", int limit = 20)
    {
        lock (_gate)
        {
            var sql = """
                SELECT s.args, s.family, COUNT(DISTINCT r.target_id) AS n
                FROM results r JOIN strategies s ON s.id=r.strategy_id LEFT JOIN networks nw ON nw.id=r.network_id
                WHERE r.status='working' AND s.l4=$l AND ($a IS NULL OR nw.asn=$a)
                GROUP BY s.id ORDER BY n DESC, s.instances, s.id LIMIT $lim
                """;
            var list = new List<(Strategy, string?, int)>();
            foreach (var r in Rows(sql, null, ("$l", l4), ("$a", asn), ("$lim", limit)))
            {
                if (TryParse((string)r[0]!) is { } s)
                    list.Add((s, (string?)r[1], (int)(long)r[2]!));
            }
            return list;
        }
    }

    // ---- sessions ----

    public long StartSession(string host, string mode, long? networkId = null, string? blockLabel = null, int port = 443, string l4 = "tcp")
    {
        lock (_gate)
        {
            long tid = TargetId(host, port, l4);
            return (long)Scalar("INSERT INTO search_sessions(uid,target_id,network_id,mode,state,block_label,started_at,updated_at) VALUES($u,$t,$n,$m,'running',$b,$ts,$ts) RETURNING id",
                ("$u", Guid.NewGuid().ToString("N")), ("$t", tid), ("$n", networkId), ("$m", mode), ("$b", blockLabel), ("$ts", Now()))!;
        }
    }

    public void UpdateSession(long id, string? state = null, string? checkpoint = null)
    {
        lock (_gate)
        {
            Exec("UPDATE search_sessions SET state=COALESCE($s,state), checkpoint=COALESCE($c,checkpoint), updated_at=$t WHERE id=$id",
                ("$s", state), ("$c", checkpoint), ("$t", Now()), ("$id", id));
        }
    }

    public SessionInfo? Session(long id) => Sessions($"WHERE ss.id={id.ToString(CultureInfo.InvariantCulture)}").SingleOrDefault();

    /// <summary>Sessions that did not finish (the app closed mid-search): offered for "continue".</summary>
    public List<SessionInfo> UnfinishedSessions() => Sessions("WHERE ss.state IN ('running','paused') ORDER BY ss.updated_at DESC");

    private List<SessionInfo> Sessions(string where)
    {
        lock (_gate)
        {
            return Rows($"SELECT ss.id, ss.uid, t.host, ss.mode, ss.state, ss.block_label, ss.checkpoint, ss.started_at, ss.updated_at FROM search_sessions ss JOIN targets t ON t.id=ss.target_id {where}")
                .Select(r => new SessionInfo((long)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, (string)r[4]!, (string?)r[5], (string?)r[6], Time(r[7]), Time(r[8])))
                .ToList();
        }
    }

    /// <summary>Strategies already tried in a session with their efficiency, so a resumed search skips them.</summary>
    public Dictionary<string, Efficiency> SessionTrials(long sessionId)
    {
        lock (_gate)
        {
            var d = new Dictionary<string, Efficiency>(StringComparer.Ordinal);
            foreach (var r in Rows("SELECT s.args, SUM(tr.ok), COUNT(*) FROM trials tr JOIN strategies s ON s.id=tr.strategy_id WHERE tr.session_id=$s GROUP BY s.id", null, ("$s", sessionId)))
                d[(string)r[0]!] = new Efficiency((int)(long)r[1]!, (int)(long)r[2]!);
            return d;
        }
    }

    public void AddTuningStep(long? sessionId, Strategy? parent, Strategy child, string mutation, Efficiency eff, bool accepted)
    {
        lock (_gate)
        {
            long? pid = parent is null ? null : StrategyId(parent);
            long cid = StrategyId(child);
            Exec("INSERT INTO tuning_steps(session_id,parent_strategy_id,strategy_id,mutation,successes,attempts,accepted,created_at) VALUES($s,$p,$c,$m,$ok,$n,$a,$t)",
                ("$s", sessionId), ("$p", pid), ("$c", cid), ("$m", mutation), ("$ok", eff.Successes), ("$n", eff.Attempts), ("$a", accepted ? 1 : 0), ("$t", Now()));
        }
    }

    public List<(string Parent, string Child, string Mutation, Efficiency Efficiency, bool Accepted)> TuningSteps(long sessionId)
    {
        lock (_gate)
        {
            return Rows("""
                SELECT COALESCE(p.args,''), c.args, ts.mutation, ts.successes, ts.attempts, ts.accepted FROM tuning_steps ts
                JOIN strategies c ON c.id=ts.strategy_id LEFT JOIN strategies p ON p.id=ts.parent_strategy_id
                WHERE ts.session_id=$s ORDER BY ts.id
                """, null, ("$s", sessionId))
                .Select(r => ((string)r[0]!, (string)r[1]!, (string)r[2]!, new Efficiency((int)(long)r[3]!, (int)(long)r[4]!), (long)r[5]! != 0))
                .ToList();
        }
    }

    // ---- checker history ----

    public void AddCheckerRun(DateTimeOffset started, TimeSpan duration, bool networkProblem, string reportJson, long? networkId = null)
    {
        lock (_gate)
        {
            Exec("INSERT INTO checker_runs(uid,network_id,started_at,duration_ms,network_problem,report) VALUES($u,$n,$s,$d,$p,$r)",
                ("$u", Guid.NewGuid().ToString("N")), ("$n", networkId), ("$s", started.ToString("O", CultureInfo.InvariantCulture)),
                ("$d", (long)duration.TotalMilliseconds), ("$p", networkProblem ? 1 : 0), ("$r", reportJson));
        }
    }

    public List<(DateTimeOffset Started, TimeSpan Duration, bool NetworkProblem, string Report)> CheckerRuns(int limit = 50)
    {
        lock (_gate)
        {
            return Rows("SELECT started_at, duration_ms, network_problem, report FROM checker_runs ORDER BY started_at DESC LIMIT $l", null, ("$l", limit))
                .Select(r => (Time(r[0]), TimeSpan.FromMilliseconds((long)r[1]!), (long)r[2]! != 0, (string)r[3]!))
                .ToList();
        }
    }

    // ---- plumbing ----

    private static StoredResult ToResult(object?[] r) => new()
    {
        StrategyHash = (string)r[0]!,
        Args = (string)r[1]!,
        Family = (string?)r[2],
        Host = (string)r[3]!,
        ClientProfile = (string)r[4]!,
        Efficiency = new Efficiency((int)(long)r[5]!, (int)(long)r[6]!),
        Status = (string)r[7]!,
        Score = r[8] is double d ? d : null,
        BlockLabel = (string?)r[9],
        Asn = r[10] is long a ? (int)a : null,
        Origin = (string)r[11]!,
        Updated = Time(r[12]),
    };

    private static Strategy? TryParse(string args)
    {
        try
        {
            return Strategy.Parse(args);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string Now() => DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset Time(object? v) => DateTimeOffset.Parse((string)v!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private SqliteCommand Command(string sql, SqliteTransaction? tx, (string, object?)[] args)
    {
        var c = _db.CreateCommand();
        c.CommandText = sql;
        c.Transaction = tx;
        foreach (var (name, value) in args)
            c.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return c;
    }

    private void Exec(string sql, params (string, object?)[] args) => Exec(sql, null, args);

    private void Exec(string sql, SqliteTransaction? tx, params (string, object?)[] args)
    {
        using var c = Command(sql, tx, args);
        c.ExecuteNonQuery();
    }

    private object? Scalar(string sql, params (string, object?)[] args)
    {
        using var c = Command(sql, null, args);
        var v = c.ExecuteScalar();
        return v is DBNull ? null : v;
    }

    private List<object?[]> Rows(string sql, SqliteTransaction? tx = null, params (string, object?)[] args)
    {
        using var c = Command(sql, tx, args);
        using var r = c.ExecuteReader();
        var list = new List<object?[]>();
        while (r.Read())
        {
            var row = new object?[r.FieldCount];
            for (int i = 0; i < row.Length; i++)
                row[i] = r.IsDBNull(i) ? null : r.GetValue(i);
            list.Add(row);
        }
        return list;
    }

    public void Dispose()
    {
        _db.Dispose();
    }
}
