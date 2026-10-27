namespace ZapretAutoTuner.Storage;

/// <summary>A row of the <c>resources</c> table.</summary>
internal sealed record ResourceRow(long Id, string Kind, string Name, int Current, int? Approved, DateTimeOffset Created, DateTimeOffset Updated);

internal sealed record ResourceVersionRow(int Version, string Origin, DateTimeOffset Created, DateTimeOffset? ApprovedAt, long Size);

/// <summary>The SQL of the strategy resources (schema v4); <see cref="ResourceStore"/> holds the rules.</summary>
public sealed partial class KnowledgeBase
{
    private const string ResourceColumns = "id, kind, name, current_version, approved_version, created_at, updated_at";

    private static ResourceRow ToResourceRow(object?[] r) =>
        new((long)r[0]!, (string)r[1]!, (string)r[2]!, (int)(long)r[3]!, r[4] is long a ? (int)a : null, Time(r[5]), Time(r[6]));

    internal ResourceRow? ResourceRow(string kind, string name)
    {
        lock (_gate)
            return Rows($"SELECT {ResourceColumns} FROM resources WHERE kind=$k AND name=$n", null, ("$k", kind), ("$n", name)).Select(ToResourceRow).SingleOrDefault();
    }

    internal List<ResourceRow> ResourceRows(string? kind)
    {
        lock (_gate)
        {
            return Rows($"SELECT {ResourceColumns} FROM resources WHERE $k IS NULL OR kind=$k ORDER BY kind, name", null, ("$k", kind))
                .Select(ToResourceRow).ToList();
        }
    }

    /// <summary>
    /// Adds a version: a new resource (<paramref name="create"/>) or the next version of an existing one. Returns the
    /// version number, or null when the precondition fails (exists / does not exist).
    /// </summary>
    internal int? AddResourceVersion(string kind, string name, byte[] content, string origin, bool create)
    {
        lock (_gate)
        {
            using var tx = _db.BeginTransaction();
            var row = Rows($"SELECT {ResourceColumns} FROM resources WHERE kind=$k AND name=$n", tx, ("$k", kind), ("$n", name)).Select(ToResourceRow).SingleOrDefault();
            if ((row is null) != create)
                return null;
            var now = Now();
            long id;
            int version;
            if (row is null)
            {
                version = 1;
                using var c = Command("INSERT INTO resources(uid,kind,name,current_version,created_at,updated_at) VALUES($u,$k,$n,1,$t,$t) RETURNING id", tx,
                    [("$u", Guid.NewGuid().ToString("N")), ("$k", kind), ("$n", name), ("$t", now)]);
                id = (long)c.ExecuteScalar()!;
            }
            else
            {
                id = row.Id;
                version = row.Current + 1;
                Exec("UPDATE resources SET current_version=$v, updated_at=$t WHERE id=$id", tx, ("$v", version), ("$t", now), ("$id", id));
            }
            Exec("INSERT INTO resource_versions(resource_id,version,content,origin,created_at) VALUES($id,$v,$c,$o,$t)", tx,
                ("$id", id), ("$v", version), ("$c", content), ("$o", origin), ("$t", now));
            tx.Commit();
            return version;
        }
    }

    internal byte[]? ResourceContent(long resourceId, int version)
    {
        lock (_gate)
            return Scalar("SELECT content FROM resource_versions WHERE resource_id=$id AND version=$v", ("$id", resourceId), ("$v", version)) as byte[];
    }

    internal List<ResourceVersionRow> ResourceVersions(long resourceId)
    {
        lock (_gate)
        {
            return Rows("SELECT version, origin, created_at, approved_at, length(content) FROM resource_versions WHERE resource_id=$id ORDER BY version", null, ("$id", resourceId))
                .Select(r => new ResourceVersionRow((int)(long)r[0]!, (string)r[1]!, Time(r[2]), r[3] is null ? null : Time(r[3]), (long)r[4]!))
                .ToList();
        }
    }

    internal void ApproveResource(long resourceId, int version)
    {
        lock (_gate)
        {
            using var tx = _db.BeginTransaction();
            var now = Now();
            Exec("UPDATE resources SET approved_version=$v, updated_at=$t WHERE id=$id", tx, ("$v", version), ("$t", now), ("$id", resourceId));
            Exec("UPDATE resource_versions SET approved_at=$t WHERE resource_id=$id AND version=$v", tx, ("$v", version), ("$t", now), ("$id", resourceId));
            tx.Commit();
        }
    }

    internal bool DeleteResource(long resourceId)
    {
        lock (_gate)
        {
            using var tx = _db.BeginTransaction();
            Exec("DELETE FROM resource_versions WHERE resource_id=$id", tx, ("$id", resourceId));
            using var c = Command("DELETE FROM resources WHERE id=$id", tx, [("$id", resourceId)]);
            var n = c.ExecuteNonQuery();
            tx.Commit();
            return n > 0;
        }
    }

    internal void SetResourceRefs(string owner, IEnumerable<(string Kind, string Name)> refs)
    {
        lock (_gate)
        {
            using var tx = _db.BeginTransaction();
            Exec("DELETE FROM resource_refs WHERE owner=$o", tx, ("$o", owner));
            foreach (var (kind, name) in refs.Distinct())
                Exec("INSERT OR IGNORE INTO resource_refs(owner,kind,name) VALUES($o,$k,$n)", tx, ("$o", owner), ("$k", kind), ("$n", name));
            tx.Commit();
        }
    }

    internal List<string> ResourceOwners(string kind, string name)
    {
        lock (_gate)
            return Rows("SELECT owner FROM resource_refs WHERE kind=$k AND name=$n ORDER BY owner", null, ("$k", kind), ("$n", name)).Select(r => (string)r[0]!).ToList();
    }

    internal List<(string Kind, string Name)> ResourceRefsOf(string owner)
    {
        lock (_gate)
            return Rows("SELECT kind, name FROM resource_refs WHERE owner=$o ORDER BY kind, name", null, ("$o", owner)).Select(r => ((string)r[0]!, (string)r[1]!)).ToList();
    }
}
