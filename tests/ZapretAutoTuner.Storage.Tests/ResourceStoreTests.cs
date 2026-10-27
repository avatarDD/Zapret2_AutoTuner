using Microsoft.Data.Sqlite;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Storage.Tests;

/// <summary>Strategy resources in the knowledge base (PLAN 4a.5): CRUD, versions, Lua approval, references.</summary>
public sealed class ResourceStoreTests : IDisposable
{
    private const string V1 = "function zt_twice(ctx, desync)\n    return VERDICT_PASS\nend\n";
    private const string V2 = "function zt_twice(ctx, desync)\n    -- second\n    return VERDICT_PASS\nend\n";

    private readonly string _dir = Directory.CreateTempSubdirectory("ztres").FullName;
    private readonly KnowledgeBase _kb;
    private readonly ResourceStore _store;

    public ResourceStoreTests()
    {
        _kb = KnowledgeBase.Open(Path.Combine(_dir, "knowledge.db"));
        _store = new ResourceStore(_kb);
    }

    public void Dispose()
    {
        _kb.Dispose();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, true);
    }

    [Fact]
    public void Crud_with_versions_for_every_kind()
    {
        var created = _store.Create(ResourceInput.Hostlist("yt", ["YouTube.com", "*.googlevideo.com"]));
        Assert.True(created.Changed);
        Assert.Equal(1, created.Info.Version);
        Assert.Equal(2, created.Info.Size);
        Assert.Single(created.Warnings); // the wildcard
        Assert.Equal(["youtube.com", "googlevideo.com"], _store.Get(ResourceKind.Hostlist, "yt")!.Data.Items);

        Assert.Throws<ResourceException>(() => _store.Create(ResourceInput.Hostlist("yt", ["a.com"])));
        Assert.Throws<ResourceException>(() => _store.Update(ResourceInput.Hostlist("nope", ["a.com"])));

        var same = _store.Update(ResourceInput.Hostlist("yt", ["youtube.com", "googlevideo.com"]));
        Assert.False(same.Changed);
        var updated = _store.Update(ResourceInput.Hostlist("yt", ["youtube.com"]), origin: "mcp");
        Assert.Equal(2, updated.Info.Version);
        Assert.Equal(["googlevideo.com"], _store.Get(ResourceKind.Hostlist, "yt", 1)!.Data.Items.Skip(1));
        Assert.Equal(["ui", "mcp"], _store.Versions(ResourceKind.Hostlist, "yt").Select(v => v.Origin));

        _store.Create(ResourceInput.Ipset("yt", ["1.2.3.4", "10.0.0.0/8"])); // same name, another kind
        _store.Create(ResourceInput.Blob("tls_wl", "0x160301"));
        _store.Create(ResourceInput.Lua("twice", V1));
        Assert.Equal([ResourceKind.Hostlist, ResourceKind.Ipset, ResourceKind.Blob, ResourceKind.LuaScript], _store.List().Select(i => i.Kind).Order());
        Assert.Equal(3, _store.Get(ResourceKind.Blob, "tls_wl")!.Info.Size);
        Assert.Single(_store.List(ResourceKind.Ipset));

        Assert.Throws<ArgumentException>(() => _store.Create(ResourceInput.Hostlist("x", ["a.com"]), origin: "somewhere"));
        _store.Delete(ResourceKind.Ipset, "yt");
        Assert.Null(_store.Get(ResourceKind.Ipset, "yt"));
        Assert.NotNull(_store.Get(ResourceKind.Hostlist, "yt"));
        Assert.Throws<ResourceException>(() => _store.Delete(ResourceKind.Ipset, "yt"));
    }

    [Fact]
    public void Lua_approval_flow()
    {
        var draft = _store.Create(ResourceInput.Lua("twice", V1), origin: "mcp").Info;
        Assert.Equal(LuaApproval.Draft, draft.Approval);
        Assert.Empty(_store.ApprovedScripts());
        // a draft is refused by the validator, with a message that says what to do
        var ctx = _store.ApplyTo(new ValidationContext());
        Assert.Equal("twice", ctx.DraftFunctions["zt_twice"]);
        Assert.Equal("func.unapproved", Assert.Single(new StrategyValidator(ctx).ValidateStrategy(Strategy.Parse("--lua-desync=zt_twice")).Errors).Code);
        Assert.Throws<ResourceException>(() => _store.ForDelivery(ResourceKind.LuaScript, "twice"));

        // the UI shows the whole text and the diff (from nothing), then approves exactly that version
        Assert.Equal(3, _store.Diff("twice").Added);
        Assert.Throws<InvalidOperationException>(() => _store.Approve("twice", 1, confirmedByUser: false));
        var approved = _store.Approve("twice", 1, confirmedByUser: true);
        Assert.Equal(LuaApproval.Approved, approved.Approval);
        var script = Assert.Single(_store.ApprovedScripts());
        Assert.Equal("zt-twice.lua", script.FileName);
        Assert.StartsWith(_store.Root, script.Path, StringComparison.Ordinal);
        Assert.Equal(V1, File.ReadAllText(script.Path));
        Assert.Equal(["zt_twice"], script.Functions);
        ctx = _store.ApplyTo(new ValidationContext());
        Assert.True(new StrategyValidator(ctx).ValidateStrategy(Strategy.Parse("--lua-desync=zt_twice:any=1")).Ok);
        Assert.Equal(script.Path, _store.ApprovedLuaPaths()["zt_twice"]);

        // an edit is a new draft; the approved version stays in effect until approved again
        var edited = _store.Update(ResourceInput.Lua("twice", V2), origin: "mcp").Info;
        Assert.Equal(LuaApproval.ApprovedWithNewDraft, edited.Approval);
        Assert.Equal(1, edited.ApprovedVersion);
        Assert.Equal(V1, File.ReadAllText(script.Path));
        Assert.Equal(V1, _store.ForDelivery(ResourceKind.LuaScript, "twice").Source);
        Assert.True(new StrategyValidator(_store.ApplyTo(new ValidationContext())).ValidateStrategy(Strategy.Parse("--lua-desync=zt_twice")).Ok);
        var diff = _store.Diff("twice");
        Assert.Equal(1, diff.Added);
        Assert.Equal(0, diff.Removed);
        Assert.Contains("+    -- second", diff.ToUnified(), StringComparison.Ordinal);
        // approving what the user did not see (a stale version) is refused
        Assert.Throws<ResourceException>(() => _store.Approve("twice", 1, confirmedByUser: true));
        _store.Approve("twice", 2, confirmedByUser: true);
        Assert.Equal(V2, File.ReadAllText(script.Path));
        Assert.Equal([false, true], _store.Versions(ResourceKind.LuaScript, "twice").Select(v => v.InEffect));

        // a file changed on disk is put back to the approved text before it is handed out
        File.WriteAllText(script.Path, "os.execute('x')");
        Assert.Equal(V2, File.ReadAllText(Assert.Single(_store.ApprovedScripts()).Path));
    }

    /// <summary>Review L1: a name with a trailing newline is not a name ($ in .NET matches before it).</summary>
    [Fact]
    public void Names_with_a_trailing_newline_are_refused()
    {
        Assert.True(ResourceNames.IsValid("yt"));
        Assert.False(ResourceNames.IsValid("yt\n"));
        Assert.Null(ResourceNames.LuaNameOf("zt-yt.lua\n"));
    }

    /// <summary>Review L1: the file is written before the database approves; a broken script is skipped, not fatal for all.</summary>
    [Fact]
    public void Approval_writes_the_file_first_and_a_broken_script_does_not_hide_the_others()
    {
        const string other = "function zt_other(ctx, desync)\n    return VERDICT_PASS\nend\n";
        _store.Create(ResourceInput.Lua("twice", V1));
        _store.Create(ResourceInput.Lua("other", other));
        _store.Approve("other", 1, confirmedByUser: true);
        // a directory where the file of "twice" goes: it cannot be written
        Directory.CreateDirectory(Path.Combine(_store.Root, "lua", "zt-twice.lua"));
        Assert.ThrowsAny<IOException>(() => _store.Approve("twice", 1, confirmedByUser: true));
        Assert.Equal(LuaApproval.Draft, _store.List(ResourceKind.LuaScript).Single(i => i.Name == "twice").Approval);

        Directory.Delete(Path.Combine(_store.Root, "lua", "zt-twice.lua"));
        _store.Approve("twice", 1, confirmedByUser: true);
        File.Delete(Path.Combine(_store.Root, "lua", "zt-twice.lua"));
        Directory.CreateDirectory(Path.Combine(_store.Root, "lua", "zt-twice.lua"));
        var problems = new List<string>();
        var scripts = _store.ApprovedScripts(problems);
        Assert.Equal("other", Assert.Single(scripts).Name);
        Assert.Contains("twice", Assert.Single(problems), StringComparison.Ordinal);
        Assert.Equal(problems, _store.ScriptProblems);
        Assert.True(_store.ApprovedLuaPaths().ContainsKey("zt_other"));
    }

    [Fact]
    public void Lua_scripts_cannot_reuse_library_or_each_others_functions()
    {
        Assert.Throws<ResourceException>(() => _store.Create(ResourceInput.Lua("mine", "function fake(ctx, desync) end")));
        _store.Create(ResourceInput.Lua("one", V1));
        var e = Assert.Throws<ResourceException>(() => _store.Create(ResourceInput.Lua("two", V1)));
        Assert.Contains("«one»", e.Ru, StringComparison.Ordinal);
    }

    [Fact]
    public void Delete_is_refused_while_a_solution_uses_the_resource()
    {
        _store.Create(ResourceInput.Hostlist("yt", ["youtube.com"]));
        _store.Create(ResourceInput.Blob("tls_wl", "0x1603"));
        _store.Create(ResourceInput.Lua("twice", V1));
        _store.Approve("twice", 1, confirmedByUser: true);
        _store.Create(ResourceInput.Hostlist("unused", ["a.com"]));

        var s = new Solution();
        s.Profiles.Add(new Profile
        {
            Name = "p", TcpPorts = "443", Hostlists = [new ListRef("yt")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=zt_twice"),
        });
        var refs = _store.SetReferences(ResourceStore.CurrentSolutionOwner, s);
        Assert.Equal(["hostlist yt", "blob tls_wl", "Lua script twice"], refs.Select(r => r.ToString()));
        Assert.Equal([ResourceStore.CurrentSolutionOwner], _store.Get(ResourceKind.Hostlist, "yt")!.Info.Owners);

        var e = Assert.Throws<ResourceException>(() => _store.Delete(ResourceKind.Hostlist, "yt"));
        Assert.Contains("текущее решение", e.Ru, StringComparison.Ordinal);
        Assert.Contains("current solution", e.En, StringComparison.Ordinal);
        Assert.Throws<ResourceException>(() => _store.Delete(ResourceKind.LuaScript, "twice"));
        _store.SetReferences("solution:home", [new ResourceRef(ResourceKind.Blob, "tls_wl")]);
        var saved = Assert.Throws<ResourceException>(() => _store.Delete(ResourceKind.Blob, "tls_wl"));
        Assert.Contains("«home»", saved.Ru, StringComparison.Ordinal);
        _store.Delete(ResourceKind.Hostlist, "unused");

        _store.ClearReferences(ResourceStore.CurrentSolutionOwner);
        _store.Delete(ResourceKind.Hostlist, "yt");
        var lua = Assert.Single(_store.ApprovedScripts()).Path;
        _store.Delete(ResourceKind.LuaScript, "twice");
        Assert.False(File.Exists(lua));
        Assert.Equal([new ResourceRef(ResourceKind.Blob, "tls_wl")], _store.ReferencesOf("solution:home"));
    }

    [Fact]
    public void Attach_fills_a_solution_with_used_resources_and_approved_lua_only()
    {
        _store.Create(ResourceInput.Hostlist("yt", ["youtube.com"]));
        _store.Create(ResourceInput.Blob("tls_wl", "0x1603"));
        _store.Create(ResourceInput.Lua("twice", V1));
        var s = new Solution();
        s.Profiles.Add(new Profile
        {
            Name = "p", TcpPorts = "443", Hostlists = [new ListRef("yt")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=zt_twice"),
        });
        Assert.Throws<ResourceException>(() => _store.AttachTo(s)); // the script is a draft
        Assert.Empty(s.Hostlists); // refused before anything is added
        _store.Approve("twice", 1, confirmedByUser: true);
        _store.Update(ResourceInput.Lua("twice", V2)); // a newer draft does not leave the PC
        s = new Solution { Profiles = s.Profiles };
        var added = _store.AttachTo(s);
        Assert.Equal(3, added.Count);
        Assert.Equal(["youtube.com"], s.Hostlists["yt"]);
        Assert.Equal([0x16, 0x03], s.Blobs["tls_wl"]);
        Assert.Equal(V1, s.LuaFiles["zt-twice.lua"]);
        // the solution now exports with the script (the exporter check passes)
        var pkg = Core.Export.Zapret2Exporter.Build(s);
        Assert.Equal(V1, pkg.TextOf("lua/zt-twice.lua"));
    }

    [Fact]
    public void Base_at_schema_v3_is_upgraded_to_resources()
    {
        var path = Path.Combine(_dir, "old.db");
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            db.Open();
            using var c = db.CreateCommand();
            c.CommandText = string.Join('\n', Schema.Migrations.Where(m => m.Version <= 3).Select(m => m.Sql))
                + "\nINSERT INTO settings(key,value,updated_at) VALUES('language','ru','2026-10-19T10:00:00Z');\nPRAGMA user_version = 3;";
            c.ExecuteNonQuery();
        }
        using (var kb = KnowledgeBase.Open(path))
        {
            Assert.Equal(4, kb.SchemaVersion);
            Assert.Equal("ru", kb.GetSetting("language"));
            var store = new ResourceStore(kb);
            store.Create(ResourceInput.Hostlist("yt", ["youtube.com"]));
        }
        using (var again = KnowledgeBase.Open(path))
        {
            Assert.Equal(Schema.Version, again.SchemaVersion);
            Assert.Single(new ResourceStore(again).List());
        }
    }
}
