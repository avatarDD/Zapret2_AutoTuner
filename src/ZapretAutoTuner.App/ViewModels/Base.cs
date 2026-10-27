using CommunityToolkit.Mvvm.ComponentModel;

namespace ZapretAutoTuner.App.ViewModels;

public abstract class PageViewModel : ObservableObject
{
    protected PageViewModel() => Loc.Loc.I.PropertyChanged += (_, _) => OnPropertyChanged(nameof(Title));

    /// <summary>The key of the page title in strings.json.</summary>
    public abstract string TitleKey { get; }

    public string Title => Loc.Loc.I[TitleKey];

    protected static Loc.Loc L => Loc.Loc.I;

    /// <summary>The page became the current one: what another page may have changed is read again.</summary>
    public virtual void OnShown()
    {
    }
}

/// <summary>What the pages share: the last run, so the report, export and monitor work on it.</summary>
public sealed class SessionState : ObservableObject
{
    private Tuning.PipelineResult? _last;

    public static SessionState I { get; } = new();

    public Tuning.PipelineResult? Last
    {
        get => _last;
        set => SetProperty(ref _last, value);
    }

    /// <summary>Every trial of the last run, for the report's attempts table.</summary>
    public List<(string Host, Core.Search.StrategyCandidate Candidate, Core.Search.TrialOutcome Outcome)> Attempts { get; } = [];

    /// <summary>The event log of the last run (the "журнал событий").</summary>
    public List<string> Log { get; } = [];
}
