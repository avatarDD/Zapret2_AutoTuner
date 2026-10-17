using ZapretAutoTuner.Probes;

namespace ZapretAutoTuner.Probes.Tests;

public class SmokeTests
{
    [Fact]
    public void Levels_are_ordered() => Assert.True(ProbeLevel.L1Handshake < ProbeLevel.L2Body);
}
