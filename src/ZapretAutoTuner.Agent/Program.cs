using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using ZapretAutoTuner.Agent;
using ZapretAutoTuner.Core;

if (args.Contains("--version"))
{
    Console.WriteLine($"{AppInfo.Name} agent {AppInfo.Version} (zapret2 {AppInfo.Zapret2Version})");
    return 0;
}

AgentOptions options;
try
{
    options = AgentOptions.Parse(args);
}
catch (ArgumentException e)
{
    Console.Error.WriteLine("ztuner-agent: " + e.Message);
    return 2;
}

await using var host = new AgentHost(options);
host.RecoverLeftovers();
if (options.CleanupOnly)
{
    await host.CleanupAsync();
    Console.WriteLine("ztuner-agent: cleanup done");
    return 0;
}

string token;
try
{
    token = options.ReadToken();
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException)
{
    Console.Error.WriteLine("ztuner-agent: cannot read the session token: " + e.Message);
    return 2;
}

// last-resort cleanup paths: SIGTERM/SIGINT/SIGHUP and normal process exit
AppDomain.CurrentDomain.ProcessExit += (_, _) => host.CleanupSync();
using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; host.RequestStop("SIGTERM"); });
using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, c => { c.Cancel = true; host.RequestStop("SIGINT"); });
using var sighup = OperatingSystem.IsWindows() ? null : PosixSignalRegistration.Create(PosixSignal.SIGHUP, c => { c.Cancel = true; host.RequestStop("SIGHUP"); });

var builder = WebApplication.CreateSlimBuilder();
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddSingleton(host);
builder.Services.AddHostedService<Watchdog>();
builder.Services.AddGrpc(o =>
{
    o.Interceptors.Add<TokenInterceptor>(token);
    o.MaxSendMessageSize = 4 << 20;
    o.MaxReceiveMessageSize = 4 << 20;
});
builder.WebHost.ConfigureKestrel(k =>
{
    if (options.Socket is not null)
    {
        if (File.Exists(options.Socket))
            File.Delete(options.Socket);
        k.ListenUnixSocket(options.Socket, l => l.Protocols = HttpProtocols.Http2);
    }
    else
    {
        k.ListenNamedPipe(options.Pipe!, l => l.Protocols = HttpProtocols.Http2);
    }
});
if (options.Pipe is not null && OperatingSystem.IsWindows())
{
    var pipeSecurity = PipeAcl.CurrentUserOnly();
    builder.WebHost.UseNamedPipes(o =>
    {
        o.PipeSecurity = pipeSecurity;
        o.CurrentUserOnly = false;
    });
}

var app = builder.Build();
app.MapGrpcService<AgentService>();

await app.StartAsync();
if (options.Socket is not null && !OperatingSystem.IsWindows())
    UnixSocket.Restrict(options.Socket, options.OwnerUid);
Console.WriteLine($"ztuner-agent: listening on {options.Socket ?? @"\\.\pipe\" + options.Pipe}");

try
{
    await Task.Delay(Timeout.Infinite, host.Stopping.Token);
}
catch (OperationCanceledException)
{
}
Console.WriteLine($"ztuner-agent: stopping ({host.StopReason})");
await host.CleanupAsync();
using (var stopCts = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
{
    try
    {
        await app.StopAsync(stopCts.Token);
    }
    catch (OperationCanceledException)
    {
    }
}
if (options.Socket is not null)
    File.Delete(options.Socket);
return 0;
