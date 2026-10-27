using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>The Validator and user Lua scripts (PLAN 4a.5): approved functions only.</summary>
public sealed class UserLuaValidatorTests
{
    private static readonly Dictionary<string, string> Approved = new(StringComparer.Ordinal) { ["zt_twice"] = "zt-twice.lua" };
    private static readonly Dictionary<string, string> Drafts = new(StringComparer.Ordinal) { ["zt_draft"] = "draft" };

    private static StrategyValidator Validator(EnginePlatform platform = EnginePlatform.Linux) =>
        new(new ValidationContext { Platform = platform }.WithUserLua(Approved, Drafts));

    [Fact]
    public void Approved_user_function_is_accepted_with_its_own_arguments()
    {
        var r = Validator().ValidateStrategy(Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_twice:count=2:mode=x --lua-desync=multisplit:pos=1"));
        Assert.True(r.Ok, r.ToString());
    }

    [Fact]
    public void Draft_and_unknown_functions_are_refused_with_clear_errors()
    {
        var draft = Validator().ValidateStrategy(Strategy.Parse("--lua-desync=zt_draft"));
        var e = Assert.Single(draft.Errors);
        Assert.Equal("func.unapproved", e.Code);
        Assert.Contains("«draft»", e.Ru, StringComparison.Ordinal);
        Assert.Contains("Approve", e.En, StringComparison.Ordinal);

        var unknown = Validator().ValidateStrategy(Strategy.Parse("--lua-desync=zt_nobody"));
        Assert.Equal("func.unknown", Assert.Single(unknown.Errors).Code);

        // without the store's context the same approved function is unknown
        Assert.False(new StrategyValidator(new ValidationContext()).ValidateStrategy(Strategy.Parse("--lua-desync=zt_twice")).Ok);
    }

    [Fact]
    public void Everything_else_is_still_checked_for_user_calls()
    {
        var r = Validator().ValidateStrategy(Strategy.Parse("--payload=bogus --lua-desync=zt_twice:blob=nope:data=%nothere:payload=xyz"));
        Assert.Contains(r.Errors, i => i.Code == "payload.unknown" && i.Ru.Contains("bogus", StringComparison.Ordinal));
        Assert.Contains(r.Errors, i => i.Code == "blob.missing");
        Assert.Contains(r.Errors, i => i.Code == "blob.subst");
        Assert.Contains(r.Errors, i => i.Code == "payload.unknown" && i.Ru.Contains("xyz", StringComparison.Ordinal)); // instance arg of the orchestrator
        Assert.True(Validator().ValidateStrategy(Strategy.Parse("--lua-desync=zt_twice:blob=fake_default_tls:pattern=0x00ff")).Ok);
    }

    [Fact]
    public void Argv_must_load_the_approved_script_file()
    {
        var profile = new Profile { Name = "p", TcpPorts = "443", Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_twice") };
        List<string> Argv(params string[] extra) => EngineArgsBuilder.Build(new EngineLaunch
        {
            Platform = EnginePlatform.Linux,
            LuaDir = "/opt/zapret2/lua",
            ExtraLuaPaths = extra,
            Profiles = [profile],
        });

        var withFile = Validator().ValidateArgv(Argv("/data/resources/lua/zt-twice.lua"));
        Assert.True(withFile.Ok, withFile.ToString());
        Assert.Contains("--lua-init=@/data/resources/lua/zt-twice.lua", Argv("/data/resources/lua/zt-twice.lua"));

        var without = Validator().ValidateArgv(Argv());
        Assert.Equal("func.user_notloaded", Assert.Single(without.Errors).Code);

        // the Agent has no store: it reads the functions of the file it is about to load
        var agent = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux });
        Assert.False(agent.ValidateArgv(Argv("/data/resources/lua/zt-twice.lua")).Ok);
        var resolved = agent.ValidateArgv(Argv("/data/resources/lua/zt-twice.lua"), null, p => p.EndsWith("zt-twice.lua", StringComparison.Ordinal) ? ["zt_twice"] : null);
        Assert.True(resolved.Ok, resolved.ToString());
        // a file that redefines a library function does not make the library function a "user" one
        var shadow = agent.ValidateArgv(Argv("/data/x.lua"), null, _ => ["fake"]);
        Assert.Contains(shadow.Errors, i => i.Code == "func.unknown");
    }
}
