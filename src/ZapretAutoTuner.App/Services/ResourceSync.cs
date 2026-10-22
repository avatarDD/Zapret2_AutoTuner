using System.ComponentModel;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// Keeps the store's "current solution" references in step with <see cref="SessionState.Last"/> (the wizard's
/// result, an imported strategy, a monitor repair, an MCP commit), so a resource the running solution uses cannot be
/// deleted (PLAN 4a.5).
/// </summary>
public sealed class ResourceSync : IDisposable
{
    private readonly ResourceStore _store;
    private readonly SessionState _session;

    public ResourceSync(ResourceStore store, SessionState session)
    {
        _store = store;
        _session = session;
        _session.PropertyChanged += OnChanged;
        Update(_session.Last?.Solution);
    }

    private void OnChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionState.Last) or null)
            Update(_session.Last?.Solution);
    }

    public void Update(Solution? solution)
    {
        try
        {
            if (solution is null)
                _store.ClearReferences(ResourceStore.CurrentSolutionOwner);
            else
                _store.SetReferences(ResourceStore.CurrentSolutionOwner, solution);
        }
        catch (Exception e) when (e is ObjectDisposedException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            // the knowledge base is closing with the app: nothing left to protect
        }
    }

    public void Dispose() => _session.PropertyChanged -= OnChanged;
}
