namespace ZapretAutoTuner.Storage;

/// <summary>
/// The local knowledge base schema (PLAN 3.2, dpi-diagnostics §6.2 and §9). Ready for P2P sharing in release 2:
/// every shareable row has a global <c>uid</c> and an <c>origin</c> (<c>local</c> or <c>peer:&lt;id&gt;</c>), strategies
/// are keyed by the hash of their canonical text, and networks are described by ASN and provider, never by address.
/// </summary>
internal static class Schema
{
    public const int Version = 1;

    /// <summary>Migrations by target version; each runs once, in order, inside a transaction.</summary>
    public static readonly IReadOnlyList<(int Version, string Sql)> Migrations =
    [
        (1, """
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- where a result was measured: shared by ASN and provider, the user's address is never stored
            CREATE TABLE networks (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                asn INTEGER,
                isp TEXT,
                country TEXT,
                label TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE INDEX networks_asn ON networks(asn);

            CREATE TABLE strategies (
                id INTEGER PRIMARY KEY,
                hash TEXT NOT NULL UNIQUE,      -- sha256 of the canonical args: the same key on every peer
                args TEXT NOT NULL,
                family TEXT,
                l4 TEXT NOT NULL DEFAULT 'tcp',
                instances INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'local'
            );

            CREATE TABLE targets (
                id INTEGER PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 443,
                l4 TEXT NOT NULL DEFAULT 'tcp',
                UNIQUE (host, port, l4)
            );

            CREATE TABLE search_sessions (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                target_id INTEGER NOT NULL REFERENCES targets(id),
                network_id INTEGER REFERENCES networks(id),
                mode TEXT NOT NULL,
                state TEXT NOT NULL,            -- running, paused, done, cancelled
                block_label TEXT,
                checkpoint TEXT,                -- JSON: where to continue after a restart
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- one attempt of one strategy on one target
            CREATE TABLE trials (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                session_id INTEGER REFERENCES search_sessions(id),
                strategy_id INTEGER NOT NULL REFERENCES strategies(id),
                target_id INTEGER NOT NULL REFERENCES targets(id),
                network_id INTEGER REFERENCES networks(id),
                client_profile TEXT NOT NULL DEFAULT 'default',
                level TEXT NOT NULL,
                ok INTEGER NOT NULL,
                error TEXT,
                bytes_in INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'local'
            );
            CREATE INDEX trials_session ON trials(session_id);

            -- aggregate per strategy, target, network and client: what the search and the export read
            CREATE TABLE results (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                strategy_id INTEGER NOT NULL REFERENCES strategies(id),
                target_id INTEGER NOT NULL REFERENCES targets(id),
                network_id INTEGER NOT NULL DEFAULT 0,  -- 0: network unknown (NULL would break the UNIQUE key)
                client_profile TEXT NOT NULL DEFAULT 'default',
                successes INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,           -- working, partial, failed
                score REAL,
                block_label TEXT,
                updated_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'local',
                shared INTEGER NOT NULL DEFAULT 0,
                UNIQUE (strategy_id, target_id, network_id, client_profile, origin)
            );
            CREATE INDEX results_target ON results(target_id, status);

            -- refinement history (§6.2a.6): parent → mutation → efficiency
            CREATE TABLE tuning_steps (
                id INTEGER PRIMARY KEY,
                session_id INTEGER REFERENCES search_sessions(id),
                parent_strategy_id INTEGER REFERENCES strategies(id),
                strategy_id INTEGER NOT NULL REFERENCES strategies(id),
                mutation TEXT NOT NULL,
                successes INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                accepted INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE checker_runs (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                network_id INTEGER REFERENCES networks(id),
                started_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                network_problem INTEGER NOT NULL,
                report TEXT NOT NULL            -- JSON rows: resource, label, light
            );

            -- release 2: peers for sharing; empty until then
            CREATE TABLE peers (
                id INTEGER PRIMARY KEY,
                peer_id TEXT NOT NULL UNIQUE,
                name TEXT,
                trust INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT
            );
            """),
    ];
}
