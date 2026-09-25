using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.AccessControl;
using System.Threading.Tasks;
using MissionController.Core;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;

namespace MissionController.UI.ViewModels;

public partial class JailDirectoryInfoItem : ObservableObject
{
    public string DirectoryName { get; init; } = string.Empty;
    public string FullPath { get; init; } = string.Empty;
    public DateTime CreatedTimeUtc { get; init; }
    public long SizeBytes { get; init; }
    public int FileCount { get; init; }
    public string SecurityStatus { get; init; } = string.Empty;

    public string FormattedFileCount => $"{FileCount} file(s)";
}

public partial class JailInspectorViewModel : ObservableObject
{
    private readonly IJailManager _jailManager;
    private readonly string _jailsBasePath;

    [ObservableProperty]
    private string _jailStatusMessage = "Jail Subsystem Active";

    [ObservableProperty]
    private int _sweptJailsCount = 0;

    [ObservableProperty]
    private int _activeJailCount = 0;

    [ObservableProperty]
    private long _totalJailStorageBytes = 0;

    [ObservableProperty]
    private ObservableCollection<JailDirectoryInfoItem> _activeJails = new();

    public JailInspectorViewModel(IJailManager jailManager)
    {
        _jailManager = jailManager;
        // The same path the jail manager provisions into, read from the one place that computes it:
        // these two were separate expressions of the same literal, and a move would have emptied this
        // page without failing anything.
        _jailsBasePath = SplatDataRoot.Layout.Jails;
    }

    [RelayCommand]
    public async Task RefreshJailsAsync()
    {
        ActiveJails.Clear();
        long totalBytes = 0;
        int count = 0;

        await Task.Run(() =>
        {
            if (!Directory.Exists(_jailsBasePath))
            {
                Directory.CreateDirectory(_jailsBasePath);
            }

            var dirs = Directory.GetDirectories(_jailsBasePath);
            foreach (var d in dirs)
            {
                try
                {
                    var dirInfo = new DirectoryInfo(d);
                    var files = dirInfo.GetFiles("*", SearchOption.AllDirectories);
                    long dirSize = 0;
                    foreach (var f in files)
                    {
                        dirSize += f.Length;
                    }

                    string sec = "Inheritance Stripped (Full Isolation)";
                    try
                    {
                        var ds = dirInfo.GetAccessControl();
                        if (ds.AreAccessRulesProtected)
                        {
                            sec = "ACL Protected (Isolated)";
                        }
                    }
                    catch
                    {
                        sec = "Jail Confined";
                    }

                    totalBytes += dirSize;
                    count++;

                    var item = new JailDirectoryInfoItem
                    {
                        DirectoryName = dirInfo.Name,
                        FullPath = dirInfo.FullName,
                        CreatedTimeUtc = dirInfo.CreationTimeUtc,
                        SizeBytes = dirSize,
                        FileCount = files.Length,
                        SecurityStatus = sec
                    };

                    App.MainWindowInstance?.DispatcherQueue?.TryEnqueue(() =>
                    {
                        ActiveJails.Add(item);
                    });
                }
                catch
                {
                    // Locked or busy directory
                }
            }
        });

        ActiveJailCount = count;
        TotalJailStorageBytes = totalBytes;
        JailStatusMessage = count == 0
            ? "Zero orphaned jails. Subsystem clean and idle."
            : $"{count} active/quarantined jail directory(ies) tracking {totalBytes / 1024.0:F1} KB.";
    }

    [RelayCommand]
    public async Task SweepOrphanJailsAsync()
    {
        int swept = await _jailManager.SweepOrphanJailsAsync();
        SweptJailsCount = swept;
        await RefreshJailsAsync();
        JailStatusMessage = $"Cleaned {swept} orphaned/stale jail directories.";
    }
}
