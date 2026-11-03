using System.ComponentModel;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// Keeps the current solution (the wizard's result, an imported strategy, a monitor repair) on disk, so closing the
/// app does not lose what the search found: the export and the protection work on it after a restart too. The file is
/// the AutoTuner bundle (strategy-export §4), the same format the export writes and the import reads; it stays in the
/// app's data folder and goes nowhere else.
/// </summary>
public sealed class SolutionStore : IDisposable
{
    public const string FileName = "current-solution.json";

    private readonly SessionState _session;
    private readonly Storage.ResourceStore? _resources;

    /// <param name="resources">The user's lists, blobs and Lua the solution may refer to: the file carries them along.</param>
    public SolutionStore(string dataDir, SessionState session, Storage.ResourceStore? resources = null)
    {
        _resources = resources;
        Path = System.IO.Path.Combine(dataDir, FileName);
        _session = session;
        _session.PropertyChanged += OnChanged;
    }

    /// <summary>Where the current solution is kept.</summary>
    public string Path { get; }

    /// <summary>The solution saved by an earlier run; null when there is none or the file does not read.</summary>
    public Solution? Load()
    {
        try
        {
            if (!File.Exists(Path))
                return null;
            var r = StrategyImporter.Import(File.ReadAllText(Path));
            return r.Solution.Profiles.Count > 0 ? r.Solution : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Puts the saved solution back as the session's current one, unless the session already has one.</summary>
    public bool Restore()
    {
        if (_session.Last?.Solution is not null || Load() is not { } s)
            return false;
        _session.Last = new Tuning.PipelineResult([], null, s);
        return true;
    }

    public void Save(Solution? s)
    {
        if (s is null || s.Profiles.Count == 0)
            return;
        try
        {
            System.Text.Json.Nodes.JsonObject bundle;
            try
            {
                bundle = ZapretGuiExporter.Bundle(s);
            }
            catch (ExportException) when (_resources is not null)
            {
                // a profile names the user's list or blob by reference: the bundle needs its content (as the export does)
                _resources.AttachTo(s);
                bundle = ZapretGuiExporter.Bundle(s);
            }
            var tmp = Path + ".tmp";
            File.WriteAllText(tmp, ZapretGuiExporter.ToJson(bundle));
            File.Move(tmp, Path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or ExportException or Core.Resources.ResourceException)
        {
            // a full disk, a read-only folder, a resource that is gone: the solution still lives in this session
        }
    }

    private void OnChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionState.Last) or null)
            Save(_session.Last?.Solution);
    }

    public void Dispose() => _session.PropertyChanged -= OnChanged;
}
