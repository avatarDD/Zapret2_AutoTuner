using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Approved user Lua in launches (PLAN 4a.5): --lua-init for the scripts the strategy calls.</summary>
public sealed class UserLuaLaunchTests
{
    [Fact]
    public void Trial_and_config_launches_load_only_the_scripts_they_call()
    {
        var options = new AgentTrialOptions
        {
            LuaDir = "/opt/zt/lua",
            Platform = EnginePlatform.Linux,
            UserLua = new Dictionary<string, string> { ["zt_twice"] = "/data/resources/lua/zt-twice.lua", ["zt_other"] = "/data/resources/lua/zt-other.lua" },
        };
        var target = new TrialTarget { Host = "example.com", Addresses = [IPAddress.Parse("192.0.2.1")] };
        var exec = new AgentTrialExecutor(null!, target, options);
        var (argv, _) = exec.BuildLaunch(new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_twice"), "user", 0, [], L4Kind.Tcp));
        Assert.Contains("--lua-init=@/data/resources/lua/zt-twice.lua", argv);
        Assert.DoesNotContain(argv, a => a.Contains("zt-other", StringComparison.Ordinal));
        var ctx = new ValidationContext { Platform = EnginePlatform.Linux }.WithUserLua(new Dictionary<string, string> { ["zt_twice"] = "zt-twice.lua" }, new Dictionary<string, string>());
        Assert.True(new StrategyValidator(ctx).ValidateArgv(argv).Ok);

        var (plain, _) = exec.BuildLaunch(new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1"), "multisplit", 0, [], L4Kind.Tcp));
        Assert.DoesNotContain(plain, a => a.Contains("/data/resources", StringComparison.Ordinal));

        var s = new Solution();
        s.Profiles.Add(new Profile { Name = "p", TcpPorts = "443", Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_other") });
        var (config, _) = ConfigCheck.BuildLaunch(s, [target], options);
        Assert.Contains("--lua-init=@/data/resources/lua/zt-other.lua", config);
    }
}
