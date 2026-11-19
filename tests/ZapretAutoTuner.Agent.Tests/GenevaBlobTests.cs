using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Geneva;
using ZapretAutoTuner.Agent.Os;

namespace ZapretAutoTuner.Agent.Tests;

public class GenevaBlobTests
{
    [Fact]
    public void A_geneva_with_extensions_gets_every_fake_of_zapret2()
    {
        var dir = Directory.CreateTempSubdirectory("geneva-blobs").FullName;
        try
        {
            var fakes = Directory.CreateDirectory(Path.Combine(dir, "fake")).FullName;
            File.WriteAllBytes(Path.Combine(fakes, "tls_clienthello_vk_com.bin"), [0x16, 3, 1]);
            File.WriteAllBytes(Path.Combine(fakes, "wireguard_initiation.bin"), [1, 0, 0, 0]);
            var m = new GenevaManager(new AgentOptions { DataDir = dir }, new AgentStateStore(dir), new LuaStore(Path.Combine(dir, "lua"), Path.Combine(dir, "engine")))
            {
                FakeDir = () => fakes,
            };
            var argv = m.WithBlobs(["run", "--ext", "-s", "S"]);
            Assert.Equal(
            [
                "run", "--ext",
                "--ext-blob", "z2_tls_clienthello_vk_com:@" + Path.Combine(fakes, "tls_clienthello_vk_com.bin"),
                "--ext-blob", "z2_wireguard_initiation:@" + Path.Combine(fakes, "wireguard_initiation.bin"),
                "-s", "S",
            ], argv);
            // a process with a fixed strategy (an "Авто" group, the detector) gets only the fakes it names
            Assert.Equal(
            [
                "run", "--ext",
                "--ext-blob", "z2_wireguard_initiation:@" + Path.Combine(fakes, "wireguard_initiation.bin"),
                "-s", "S",
            ], m.WithBlobs(["run", "--ext", "-s", "S"], ["z2_wireguard_initiation"]));
            Assert.Equal(["run", "--ext", "-s", "S"], m.WithBlobs(["run", "--ext", "-s", "S"], []));
            // without the extensions geneva does not know --ext-blob; without zapret2 there is nothing to hand
            Assert.Equal(["run", "-s", "S"], m.WithBlobs(["run", "-s", "S"]));
            m.FakeDir = () => null;
            Assert.Equal(["evolve", "--ext"], m.WithBlobs(["evolve", "--ext"]));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void A_target_takes_only_its_own_lines_of_the_old_common_database()
    {
        string[] db =
        [
            "{\"s\":\"[TCP:flags:PA]-drop-| \\/\",\"t\":\"external:a.example:443\",\"runs\":3,\"ok\":2}",
            "{\"s\":\"[TCP:flags:PA]-drop-| \\/\",\"t\":\"external:b.example:443\",\"runs\":1,\"ok\":0}",
            "not json",
            "",
        ];
        var mine = GenevaManager.LinesOf(db, "external:a.example:443");
        Assert.Equal([db[0]], mine);
        Assert.Empty(GenevaManager.LinesOf(db, "external:c.example:443"));
    }
}
