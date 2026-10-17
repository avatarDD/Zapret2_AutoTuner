using ZapretAutoTuner.Core;

if (args.Contains("--version"))
{
    Console.WriteLine($"{AppInfo.Name} agent {AppInfo.Version} (zapret2 {AppInfo.Zapret2Version})");
    return 0;
}

Console.Error.WriteLine("ztuner-agent: the IPC server arrives in phase 1");
return 2;
