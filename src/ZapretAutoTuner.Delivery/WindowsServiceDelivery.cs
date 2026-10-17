using Google.Protobuf;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Delivery;

/// <summary>Installs or removes the winws2 service through the Agent (PLAN 5.3); the UI itself has no rights.</summary>
public static class WindowsServiceDelivery
{
    public static List<DeliveryStep> Plan(ExportPackage pkg) =>
    [
        new("Остановить и удалить прежнюю службу zt_winws2, если есть", "Stop and delete the previous zt_winws2 service, if any"),
        new($"Скопировать winws2 и {pkg.Files.Count} файлов экспорта в защищённую папку ProgramData", $"Copy winws2 and {pkg.Files.Count} export files into a protected ProgramData folder"),
        new("Создать службу zt_winws2 с автозапуском и запустить её", "Create the zt_winws2 service with automatic start and start it"),
    ];

    /// <param name="confirmedByUser">Set by the confirmation dialog only.</param>
    public static async Task<ServiceReply> InstallAsync(Agent.AgentClient agent, ExportPackage pkg, bool confirmedByUser, CancellationToken ct = default)
    {
        if (pkg.Format != "winws2")
            throw new ArgumentException("нужен экспорт winws2 / a winws2 export is required", nameof(pkg));
        if (!confirmedByUser)
            throw new InvalidOperationException("установка службы без подтверждения запрещена / installing the service needs the user's confirmation");
        var request = new InstallServiceRequest();
        foreach (var (path, bytes) in pkg.Files.Where(f => f.Key == "zt-config.txt" || f.Key.StartsWith("lists/", StringComparison.Ordinal) || f.Key.StartsWith("files/", StringComparison.Ordinal)))
            request.Files[path] = ByteString.CopyFrom(bytes);
        return await agent.InstallServiceAsync(request, cancellationToken: ct);
    }

    public static async Task<ServiceReply> RemoveAsync(Agent.AgentClient agent, bool confirmedByUser, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("удаление службы без подтверждения запрещено / removing the service needs the user's confirmation");
        return await agent.RemoveServiceAsync(new RemoveServiceRequest(), cancellationToken: ct);
    }
}
