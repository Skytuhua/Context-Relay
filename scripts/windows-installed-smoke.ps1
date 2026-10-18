#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidateDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This driver exercises a disposable hosted runner's real profile and keystore.
# It is deliberately not a host-side installer test or an application test mode.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ARCH -ne 'X64' -or $env:GITHUB_JOB -ne 'installed-smoke' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $ExpectedSourceCommit -ne $env:GITHUB_SHA) {
    throw 'Installed smoke requires the dedicated ephemeral GitHub-hosted Windows x64 job.'
}

function Assert-RegularPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Smoke paths must not traverse reparse points.'
        }
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($parent) { $parent.FullName } else { $null }
    }
}

function Get-ContainedPath([string]$Root, [string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative) -or
        $Relative -match '[\x00-\x1f<>:"|?*]' -or $Relative.Contains('`')) {
        throw 'Invalid relative artifact path.'
    }
    foreach ($segment in ($Relative -split '[\\/]')) {
        if (-not $segment -or $segment -in @('.', '..') -or $segment -match '[. ]$' -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)') {
            throw 'Ambiguous artifact path component.'
        }
    }
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Artifact path escapes its root.'
    }
    return $full
}

function Read-BoundedText([string]$Path, [long]$Limit = 1048576) {
    Assert-RegularPath $Path
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or $item.Length -gt $Limit) { throw 'Invalid evidence file size or type.' }
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
}

function Assert-FileRecord([string]$Root, $Record) {
    if ($Record.name -isnot [string] -or $Record.sha256 -notmatch '^[a-f0-9]{64}$' -or
        ($Record.bytes -isnot [long] -and $Record.bytes -isnot [int]) -or $Record.bytes -le 0) {
        throw 'Invalid artifact file record.'
    }
    $file = Get-ContainedPath $Root $Record.name
    Assert-RegularPath $file
    $item = Get-Item -LiteralPath $file
    if ($item.PSIsContainer -or $item.Length -ne $Record.bytes -or
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Record.sha256) {
        throw ('Artifact bytes differ: ' + $Record.name)
    }
    return $file
}

function Get-ProductEntries {
    foreach ($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root | ForEach-Object {
                $entry = Get-ItemProperty -LiteralPath $_.PSPath
                if ($entry.PSObject.Properties['DisplayName'] -and $entry.DisplayName -eq 'Context Relay') {
                    $entry
                }
            }
        }
    }
}

function Get-WebViewObservation {
    $versions = @()
    foreach ($root in @('HKCU:\Software\Microsoft\EdgeUpdate\Clients',
        'HKLM:\Software\Microsoft\EdgeUpdate\Clients',
        'HKLM:\Software\WOW6432Node\Microsoft\EdgeUpdate\Clients')) {
        if (Test-Path -LiteralPath $root) {
            foreach ($child in Get-ChildItem -LiteralPath $root) {
                $item = Get-ItemProperty -LiteralPath $child.PSPath
                if ($item.PSObject.Properties['name'] -and $item.name -like '*WebView2*' -and
                    $item.PSObject.Properties['pv']) { $versions += [string]$item.pv }
            }
        }
    }
    return [ordered]@{ registryVersions = @($versions | Sort-Object -Unique); absenceQualified = $false }
}

function Wait-TaskResult($Task, [int]$Seconds, [string]$Label) {
    if (-not $Task.Wait([TimeSpan]::FromSeconds($Seconds))) { throw ($Label + ' exceeded its deadline.') }
    return $Task.GetAwaiter().GetResult()
}

function Start-OwnedProcess([string]$File, [string[]]$Arguments = @(), [bool]$Visible = $false) {
    Assert-RegularPath $File
    # All allowed arguments are fixed, whitespace-free protocol/installer switches.
    foreach ($argument in $Arguments) {
        if ($argument -notmatch '^(?:/S|--shutdown|--harness|codex)$') { throw 'Unexpected process argument.' }
    }
    $environment = [Collections.Generic.SortedDictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('SystemRoot', 'WINDIR', 'SystemDrive', 'COMSPEC', 'TEMP', 'TMP',
        'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'USERNAME', 'USERDOMAIN',
        'PROGRAMDATA', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'PUBLIC',
        'ALLUSERSPROFILE', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'OS')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $value) { $environment[$name] = $value }
    }
    $environment['PATH'] = $script:childPath
    $child = $script:processJob.Start($File, ($Arguments -join ' '), $script:neutralDirectory, $environment, $Visible)
    $owned = [pscustomobject]@{
        Process = $child.Process; Path = [IO.Path]::GetFullPath($File)
        Input = $child.Input; Output = $child.Output
        ErrorTask = [InstalledSmokeIO]::DrainAsync($child.Error, 65536)
    }
    $script:ownedProcesses.Add($owned)
    return $owned
}

function Assert-OwnedProcess($Owned) {
    if ($Owned.Process.HasExited) { return }
    if (-not [string]::Equals($Owned.Process.MainModule.FileName, $Owned.Path, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Process image does not match its captured installed path.'
    }
}

function Complete-Process($Owned, [int]$Seconds, [int]$ExpectedExit = 0) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $output = [InstalledSmokeIO]::DrainAsync($Owned.Output, 65536)
    $Owned.Input.Close()
    if (-not $Owned.Process.WaitForExit($Seconds * 1000)) { throw 'Process exceeded its deadline.' }
    # NSIS may hand off to a self-copy that still owns the standard handles.
    # Its output uses the remaining stage budget, not a new five-second budget.
    foreach ($task in @($output, $Owned.ErrorTask)) {
        $remaining = [int][Math]::Max(0, [Math]::Floor(($deadline - [DateTime]::UtcNow).TotalMilliseconds))
        if (-not $task.Wait($remaining)) { throw 'Process output exceeded the stage deadline.' }
        $null = $task.GetAwaiter().GetResult()
    }
    if ($Owned.Process.ExitCode -ne $ExpectedExit) { throw ('Process returned unexpected exit code ' + $Owned.Process.ExitCode) }
}

function Wait-VisibleElement($Desktop, [string]$Name, [int]$Seconds, [bool]$Invoke = $false) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Desktop.Process.HasExited) { throw 'Installed desktop exited before rendered readiness.' }
        $Desktop.Process.Refresh()
        $handle = $Desktop.Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) {
            # The individual provider call is bounded too; FindAll may hang.
            $probe = [InstalledSmokeUI]::FindAsync($handle, $Desktop.Process.Id, $Name, $Invoke)
            if (Wait-TaskResult $probe 5 ('UI Automation: ' + $Name)) { return }
        }
        Start-Sleep -Milliseconds 250
    }
    throw ('Visible UI was not ready: ' + $Name + '. An interactive accessible hosted desktop is required.')
}

function Read-McpReply($Bridge, $Reader, [int]$ExpectedId) {
    $line = Wait-TaskResult ($Reader.ReadLineAsync()) 75 'MCP reply'
    if (-not $line) { throw 'MCP ended before its correlated reply.' }
    $reply = $line | ConvertFrom-Json
    if ($reply.jsonrpc -cne '2.0' -or ($reply.id -isnot [int] -and $reply.id -isnot [long]) -or $reply.id -ne $ExpectedId -or
        $reply.PSObject.Properties['error'] -or -not $reply.PSObject.Properties['result']) {
        throw 'MCP reply identity or success envelope is invalid.'
    }
    if ($Bridge.ErrorTask.IsFaulted) { throw 'MCP diagnostic output exceeded its bound.' }
    return $reply.result
}

function Send-McpMessage($Bridge, $Message) {
    $line = ConvertTo-Json -InputObject $Message -Depth 12 -Compress
    $null = Wait-TaskResult ($Bridge.Input.WriteLineAsync($line)) 5 'MCP input'
    $null = Wait-TaskResult ($Bridge.Input.FlushAsync()) 5 'MCP input flush'
}

function Test-InstalledMcp([string]$BridgePath, [string]$Version) {
    $bridge = Start-OwnedProcess $BridgePath @('--harness', 'codex')
    $reader = [InstalledSmokeIO]::new($bridge.Output, 1048576, 4194304)
    Send-McpMessage $bridge @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{
        protocolVersion = '2025-11-25'; capabilities = @{}; clientInfo = @{ name = 'windows-installer-smoke'; version = '1' }
    } }
    $initialized = Read-McpReply $bridge $reader 1
    if ($initialized.protocolVersion -cne '2025-11-25' -or $initialized.serverInfo.name -cne 'context-relay' -or
        $initialized.serverInfo.version -cne $Version) { throw 'Unexpected installed MCP server identity.' }
    Send-McpMessage $bridge @{ jsonrpc = '2.0'; method = 'notifications/initialized' }
    Send-McpMessage $bridge @{ jsonrpc = '2.0'; id = 2; method = 'tools/list'; params = @{} }
    $listed = Read-McpReply $bridge $reader 2
    if (@($listed.tools | Where-Object { $_.name -ceq 'context_relay_status' }).Count -ne 1) {
        throw 'Installed bridge did not advertise the normal status tool.'
    }
    Send-McpMessage $bridge @{ jsonrpc = '2.0'; id = 3; method = 'tools/call'; params = @{
        name = 'context_relay_status'; arguments = @{}
    } }
    $called = Read-McpReply $bridge $reader 3
    if ($called.PSObject.Properties['isError'] -and $called.isError) { throw 'Authenticated MCP status failed.' }
    $status = $called.structuredContent
    if ($status.vault -cne 'unlocked' -or $null -ne $status.resolvedProject -or $status.access.mode -cne 'default' -or
        $status.protocol.min.major -ne 1 -or $status.protocol.min.minor -lt 1 -or
        $status.protocol.min.major -ne $status.protocol.max.major -or $status.protocol.min.minor -ne $status.protocol.max.minor) {
        throw 'Installed daemon did not return the expected fresh authenticated status.'
    }
    $bridge.Input.Close()
    if (-not $bridge.Process.WaitForExit(10000) -or $bridge.Process.ExitCode -ne 0) { throw 'MCP did not close cleanly after EOF.' }
    $null = Wait-TaskResult $bridge.ErrorTask 5 'MCP diagnostics'
    return [ordered]@{ serverVersion = $initialized.serverInfo.version; protocol = $status.protocol; vault = $status.vault }
}

function Capture-InstalledDaemon([string]$Path) {
    # Enumerate only the held job's children and retain their open process handles.
    # No WMI call, PID-only ownership, or name-based termination is involved.
    $matches = [Collections.Generic.List[object]]::new()
    try {
        foreach ($process in $script:processJob.GetProcesses()) {
            $retained = $false
            try {
                if ($process.HasExited) { continue }
                try { $image = $process.MainModule.FileName }
                catch {
                    # A short-lived WebView/NSIS sibling may exit during enumeration.
                    # A live process whose image cannot be read still fails closed.
                    if ($process.HasExited) { continue }
                    throw
                }
                if ([string]::Equals($image, $Path, [StringComparison]::OrdinalIgnoreCase)) {
                    $matches.Add($process)
                    $retained = $true
                }
            } finally { if (-not $retained) { $process.Dispose() } }
        }
        if ($matches.Count -ne 1 -or $matches[0].HasExited) { throw 'Expected exactly one live daemon from the installed directory.' }
    } catch {
        foreach ($process in $matches) { $process.Dispose() }
        throw
    }
    $owned = [pscustomobject]@{ Process = $matches[0]; Path = $Path; ErrorTask = $null }
    Assert-OwnedProcess $owned
    $script:ownedProcesses.Add($owned)
    return $owned
}

function Close-Desktop($Desktop) {
    if ($Desktop -and -not $Desktop.Process.HasExited) {
        Assert-OwnedProcess $Desktop
        if (-not $Desktop.Process.CloseMainWindow() -or -not $Desktop.Process.WaitForExit(20000)) {
            throw 'Installed desktop did not close through its own window.'
        }
    }
}

function Stop-InstalledDaemon([string]$Path) {
    Complete-Process (Start-OwnedProcess $Path @('--shutdown')) 60
    foreach ($owned in $script:ownedProcesses) {
        if ($owned.Path -eq $Path -and -not $owned.Process.HasExited) { throw 'Captured installed daemon survived authenticated shutdown.' }
    }
}

# All runtime helpers are driver-side .NET code; no application/daemon test flag,
# developer server, debugger endpoint, synthetic token, or fake profile is used.
function Initialize-SmokeHelpers {
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, WindowsBase
Add-Type -ReferencedAssemblies @('System.dll', 'System.Core.dll', [System.Windows.Automation.AutomationElement].Assembly.Location,
    [System.Windows.Automation.ControlType].Assembly.Location, [System.Windows.Rect].Assembly.Location) -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Automation;
public sealed class InstalledSmokeChild {
    public Process Process;
    public StreamWriter Input;
    public StreamReader Output, Error;
}
public sealed class InstalledSmokeJob : IDisposable {
    IntPtr job;
    const uint CREATE_SUSPENDED = 0x4, CREATE_UNICODE_ENVIRONMENT = 0x400;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x80000, CREATE_NO_WINDOW = 0x8000000;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long ProcessTime, JobTime; public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
        public BasicLimits Basic; public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        public uint Size; public IntPtr Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, FillAttribute, Flags;
        public ushort ShowWindow, ReservedSize;
        public IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx {
        public StartupInfo Startup; public IntPtr Attributes;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
        public IntPtr Process, Thread; public uint ProcessId, ThreadId;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool included);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr attributes, int count, uint flags, ref IntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr attributes, uint flags, IntPtr attribute, IntPtr value, IntPtr bytes, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory,
        ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static Win32Exception Failure(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }
    public InstalledSmokeJob() {
        job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Failure("Create smoke process job");
        ExtendedLimits limits = new ExtendedLimits();
        limits.Basic.Flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits)))) {
            Win32Exception error = Failure("Set smoke job lifetime"); Dispose(); throw error;
        }
    }
    public InstalledSmokeChild Start(string file, string arguments, string directory,
        IDictionary<string, string> environment, bool visible) {
        if (job == IntPtr.Zero) throw new ObjectDisposedException("Smoke job");
        // Only these three explicitly listed pipe handles reach the child.
        // Job assignment occurs while its primary thread is suspended, before
        // NSIS, the desktop, or the bridge can spawn any descendants.
        AnonymousPipeServerStream input = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        AnonymousPipeServerStream output = null, error = null;
        IntPtr attributes = IntPtr.Zero, handleList = IntPtr.Zero, environmentBlock = IntPtr.Zero;
        bool attributesReady = false, succeeded = false;
        Exception launchFailure = null;
        ProcessInfo native = new ProcessInfo(); Process captured = null;
        try {
            output = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            error = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            IntPtr bytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
            if (bytes == IntPtr.Zero) throw Failure("Size process attributes");
            attributes = Marshal.AllocHGlobal(bytes);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes)) throw Failure("Initialize process attributes");
            attributesReady = true;
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, input.ClientSafePipeHandle.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size, output.ClientSafePipeHandle.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, error.ClientSafePipeHandle.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handleList,
                new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw Failure("Restrict inherited handles");
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in environment) block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
            block.Append('\0'); environmentBlock = Marshal.StringToHGlobalUni(block.ToString());
            StartupInfoEx startup = new StartupInfoEx();
            startup.Startup.Size = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
            startup.Startup.Flags = 0x100; // STARTF_USESTDHANDLES
            startup.Startup.Input = input.ClientSafePipeHandle.DangerousGetHandle();
            startup.Startup.Output = output.ClientSafePipeHandle.DangerousGetHandle();
            startup.Startup.Error = error.ClientSafePipeHandle.DangerousGetHandle();
            startup.Attributes = attributes;
            uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
            if (!visible) flags |= CREATE_NO_WINDOW;
            StringBuilder command = new StringBuilder("\"" + file + "\"" + (arguments.Length == 0 ? "" : " " + arguments));
            if (!CreateProcessW(file, command, IntPtr.Zero, IntPtr.Zero, true, flags,
                environmentBlock, directory, ref startup, out native)) throw Failure("Create suspended smoke child");
            if (!AssignProcessToJobObject(job, native.Process)) throw Failure("Own suspended smoke child");
            captured = Process.GetProcessById((int)native.ProcessId);
            IntPtr retainedHandle = captured.Handle; // retain identity before resuming, including very short-lived children
            input.DisposeLocalCopyOfClientHandle(); output.DisposeLocalCopyOfClientHandle(); error.DisposeLocalCopyOfClientHandle();
            InstalledSmokeChild child = new InstalledSmokeChild();
            child.Process = captured;
            child.Input = new StreamWriter(input, new UTF8Encoding(false, true)); child.Input.NewLine = "\n";
            child.Output = new StreamReader(output, new UTF8Encoding(false, true), false);
            child.Error = new StreamReader(error, new UTF8Encoding(false, true), false);
            if (ResumeThread(native.Thread) == UInt32.MaxValue) throw Failure("Resume owned smoke child");
            succeeded = true; return child;
        } catch (Exception failure) { launchFailure = failure; throw;
        } finally {
            Exception cleanupFailure = null;
            if (!succeeded) {
                // Assignment failure cannot run even one instruction in an unowned target.
                if (native.Process != IntPtr.Zero) {
                    bool terminated = TerminateProcess(native.Process, 1);
                    int terminateError = terminated ? 0 : Marshal.GetLastWin32Error();
                    uint waited = WaitForSingleObject(native.Process, 10000);
                    if (waited != 0) cleanupFailure = new InvalidOperationException(
                        "Suspended child cleanup did not complete: termination=" + terminated +
                        ", terminationError=" + terminateError + ", waitResult=" + waited);
                }
                if (captured != null) captured.Dispose();
                input.Dispose(); if (output != null) output.Dispose(); if (error != null) error.Dispose();
            }
            if (native.Thread != IntPtr.Zero) CloseHandle(native.Thread);
            if (native.Process != IntPtr.Zero) CloseHandle(native.Process);
            if (attributesReady) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
            if (cleanupFailure != null) throw new AggregateException("Launch and suspended-child cleanup failed", launchFailure, cleanupFailure);
        }
    }
    public Process[] GetProcesses() {
        const int capacity = 1024;
        IntPtr information = Marshal.AllocHGlobal(8 + IntPtr.Size * capacity);
        List<Process> processes = new List<Process>();
        try {
            uint returned;
            if (!QueryInformationJobObject(job, 3, information, (uint)(8 + IntPtr.Size * capacity), out returned))
                throw Failure("Read bounded smoke job process list");
            int count = Marshal.ReadInt32(information, 4);
            if (count < 0 || count > capacity) throw new InvalidOperationException("Smoke job process bound");
            for (int i = 0; i < count; i++) {
                Process process = null;
                try {
                    long id = Marshal.ReadIntPtr(information, 8 + i * IntPtr.Size).ToInt64();
                    process = Process.GetProcessById(checked((int)id));
                    bool included;
                    if (!IsProcessInJob(process.Handle, job, out included)) throw Failure("Attest smoke process membership");
                    if (included && !process.HasExited) { processes.Add(process); process = null; }
                } catch (ArgumentException) { /* exited before its handle could be opened */ }
                catch (Win32Exception) {
                    // Do not suppress live access/image failures. HasExited must
                    // establish the race before an unsuccessful handle open is ignored.
                    if (process == null || !process.HasExited) throw;
                }
                catch (InvalidOperationException) {
                    // .NET Framework may report the same gone-PID race with
                    // InvalidOperationException instead of Win32Exception.
                    if (process == null || !process.HasExited) throw;
                }
                finally { if (process != null) process.Dispose(); }
            }
            return processes.ToArray();
        } catch { foreach (Process process in processes) process.Dispose(); throw; }
        finally { Marshal.FreeHGlobal(information); }
    }
    int ActiveCount() {
        IntPtr information = Marshal.AllocHGlobal(48);
        try {
            uint returned;
            if (!QueryInformationJobObject(job, 1, information, 48, out returned)) throw Failure("Read smoke job accounting");
            return Marshal.ReadInt32(information, 40);
        } finally { Marshal.FreeHGlobal(information); }
    }
    public bool WaitForEmpty(int milliseconds) {
        Stopwatch clock = Stopwatch.StartNew();
        while (ActiveCount() != 0) {
            if (clock.ElapsedMilliseconds >= milliseconds) return false;
            Thread.Sleep(100);
        }
        return true;
    }
    public void Terminate() { if (!TerminateJobObject(job, 1)) throw Failure("Terminate smoke-owned process tree"); }
    public void Dispose() { if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; } }
}
public sealed class InstalledSmokeIO {
    readonly StreamReader reader; readonly int frameLimit, totalLimit;
    readonly char[] buffer = new char[4096]; string pending = ""; int total;
    public InstalledSmokeIO(StreamReader reader, int frameLimit, int totalLimit) {
        this.reader = reader; this.frameLimit = frameLimit; this.totalLimit = totalLimit;
    }
    public async Task<string> ReadLineAsync() {
        while (true) {
            int newline = pending.IndexOf('\n');
            if (newline >= 0) {
                if (newline > frameLimit) throw new InvalidDataException("MCP frame bound");
                string line = pending.Substring(0, newline).TrimEnd('\r');
                pending = pending.Substring(newline + 1); return line;
            }
            if (pending.Length > frameLimit) throw new InvalidDataException("MCP frame bound");
            int count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (count == 0) throw new EndOfStreamException("MCP ended before newline");
            total += count;
            if (total > totalLimit) throw new InvalidDataException("MCP output bound");
            pending += new string(buffer, 0, count);
        }
    }
    public static async Task<string> DrainAsync(StreamReader reader, int limit) {
        char[] buffer = new char[4096]; StringBuilder result = new StringBuilder();
        int count;
        while ((count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0) {
            if (result.Length + count > limit) throw new InvalidDataException("Process output bound");
            result.Append(buffer, 0, count);
        }
        return result.ToString();
    }
}
public static class InstalledSmokeUI {
    public static Task<bool> FindAsync(IntPtr handle, int processId, string name, bool invoke) {
        return Task.Run(() => {
            AutomationElement root = AutomationElement.FromHandle(handle);
            if (root.Current.ProcessId != processId) throw new InvalidOperationException("Window owner mismatch");
            Condition condition = new PropertyCondition(AutomationElement.NameProperty, name);
            if (invoke) condition = new AndCondition(condition,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button));
            foreach (AutomationElement element in root.FindAll(TreeScope.Descendants, condition)) {
                if (element.Current.IsOffscreen || !element.Current.IsEnabled) continue;
                if (invoke) {
                    object pattern;
                    if (!element.TryGetCurrentPattern(InvokePattern.Pattern, out pattern)) continue;
                    ((InvokePattern)pattern).Invoke();
                }
                return true;
            }
            return false;
        });
    }
}
'@
}

$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
Assert-RegularPath $runnerRoot
foreach ($directory in @($CandidateDirectory, $EvidenceDirectory)) {
    if (-not [IO.Path]::GetFullPath($directory).StartsWith($runnerRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Candidate and evidence directories must be inside this hosted job temporary directory.'
    }
}
Assert-RegularPath $CandidateDirectory
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be new for this run.' }
Assert-RegularPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($EvidenceDirectory)))
$null = New-Item -ItemType Directory -Path $EvidenceDirectory
Assert-RegularPath $EvidenceDirectory
$script:neutralDirectory = Get-ContainedPath $EvidenceDirectory 'working-directory'
$null = New-Item -ItemType Directory -Path $script:neutralDirectory
$script:childPath = @([Environment]::SystemDirectory, $env:SystemRoot,
    (Join-Path $env:SystemRoot 'System32\Wbem'), (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0')) -join ';'
$script:ownedProcesses = [Collections.Generic.List[object]]::new()
$script:processJob = $null
$script:evidence = [ordered]@{
    schema = 'context-relay-windows-installed-smoke-v1'; sourceCommit = $ExpectedSourceCommit
    startedAt = [DateTime]::UtcNow.ToString('o'); result = 'running'; forcedCleanup = $false
    runner = [ordered]@{ image = $env:ImageOS; imageVersion = $env:ImageVersion; osVersion = [Environment]::OSVersion.VersionString
        interactive = [Environment]::UserInteractive; sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        elevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    childPath = $script:childPath; webViewBefore = Get-WebViewObservation
    stages = [ordered]@{}; cleanup = [ordered]@{}
    limitations = @('Hosted image retains machine-installed runtimes and tools; child PATH is restricted.',
        'WebView2 absence, disconnected provisioning, standard-user integrity, clean OS, and real coding harnesses are not qualified.',
        'Empty-vault search readiness qualifies packaged model/runtime initialization, not embedding inference or search quality.',
        'This smoke does not replace installed upgrade, hosted-account, or release qualification.')
}
$desktop = $null; $daemonPath = $null; $uninstaller = $null; $failure = $null
$localData = [Environment]::GetFolderPath('LocalApplicationData')
$installRoot = Join-Path $localData 'Context Relay'
$vaultPath = Join-Path $installRoot 'vault-v1.db'
$expectedBinaries = @('context-relay-desktop.exe', 'context-relay-contextd.exe', 'context-relay-context-mcp.exe',
    'context-relay-native-helper.exe', 'context-relay-sidecar-installer.exe')
try {
    if (-not [Environment]::UserInteractive) { throw 'Hosted runner has no interactive desktop for the required visible UI assertions.' }
    Assert-RegularPath $localData
    if (Test-Path -LiteralPath $installRoot) { throw 'Existing Context Relay profile or installation; refusing installer execution.' }
    if (@(Get-ProductEntries).Count -ne 0) { throw 'Existing Context Relay uninstall registration; refusing installer execution.' }
    if (@(Get-Process | Where-Object { $_.ProcessName -in @('context-relay-desktop', 'context-relay-contextd',
        'context-relay-context-mcp', 'context-relay-native-helper', 'context-relay-sidecar-installer') }).Count -ne 0) {
        throw 'Existing Context Relay process; refusing installer shutdown hooks.'
    }
    Initialize-SmokeHelpers
    $script:processJob = [InstalledSmokeJob]::new()
    $provenancePath = Get-ContainedPath $CandidateDirectory 'provenance.json'
    $provenance = (Read-BoundedText $provenancePath) | ConvertFrom-Json
    if ($provenance.source_commit -cne $ExpectedSourceCommit -or $provenance.target -cne 'x86_64-pc-windows-msvc' -or
        [string]$provenance.workflow.run_id -cne $env:GITHUB_RUN_ID -or
        $provenance.workflow.sha -cne $env:GITHUB_WORKFLOW_SHA -or $provenance.workflow.ref -cne $env:GITHUB_WORKFLOW_REF -or
        [string]$provenance.workflow.run_attempt -notmatch '^[1-9][0-9]*$' -or
        $provenance.version -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$' -or
        $provenance.installer.name -cne ('Context Relay_' + $provenance.version + '_x64-setup.exe')) {
        throw 'Candidate provenance does not match this source/run/target.'
    }
    $sums = (Read-BoundedText (Get-ContainedPath $CandidateDirectory 'SHA256SUMS')) -split '\r?\n' | Where-Object { $_ }
    if (@($sums).Count -ne 3) { throw 'Expected three exact candidate checksum entries.' }
    $sumNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $sums) {
        if ($line -cnotmatch '^([a-f0-9]{64})  (.+)$') { throw 'Malformed candidate checksum entry.' }
        $digest = $Matches[1]; $name = $Matches[2]
        if ($name -cnotin @($provenance.installer.name, 'provenance.json', 'sbom.cdx.json') -or -not $sumNames.Add($name)) {
            throw 'Unexpected or duplicate candidate checksum entry.'
        }
        $file = Get-ContainedPath $CandidateDirectory $name
        Assert-RegularPath $file
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'Candidate checksum differs.' }
    }
    $installer = Assert-FileRecord $CandidateDirectory $provenance.installer
    $script:evidence.candidate = [ordered]@{ installer = $provenance.installer; sourceCommit = $provenance.source_commit
        buildRunId = $provenance.workflow.run_id; buildRunAttempt = $provenance.workflow.run_attempt
        provenanceSha256 = (Get-FileHash -LiteralPath $provenancePath -Algorithm SHA256).Hash.ToLowerInvariant() }
    Complete-Process (Start-OwnedProcess $installer @('/S')) 600
    Assert-RegularPath $installRoot
    $script:evidence.stages.install = 'passed'
    $entries = @(Get-ProductEntries)
    if ($entries.Count -ne 1 -or $entries[0].PSPath -notlike '*HKEY_CURRENT_USER*' -or
        -not [string]::Equals(([IO.Path]::GetFullPath($entries[0].InstallLocation)).TrimEnd('\'), $installRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer did not register the expected current-user destination.'
    }
    $uninstallValue = [string]$entries[0].UninstallString
    if ($uninstallValue -match '^"([^"\r\n]+\.exe)"$') { $uninstallPath = $Matches[1] }
    elseif ($uninstallValue -match '^[^"\r\n]+\.exe$') { $uninstallPath = $uninstallValue }
    else { throw 'Unrecognized installed uninstall command; refusing shell evaluation.' }
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($uninstallPath), $installRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Uninstaller is not directly inside the installed directory.'
    }
    Assert-RegularPath $uninstallPath
    $uninstaller = [pscustomobject]@{ path = $uninstallPath; sha256 = (Get-FileHash -LiteralPath $uninstallPath -Algorithm SHA256).Hash }
    $expectedResources = @('LICENSE', 'THIRD_PARTY_NOTICES.md', 'search/model/model_optimized.onnx',
        'search/model/config.json', 'search/model/special_tokens_map.json', 'search/model/tokenizer.json', 'search/model/tokenizer_config.json',
        'search/runtime/vcruntime140.dll', 'search/runtime/vcruntime140_1.dll', 'search/runtime/msvcp140.dll',
        'search/runtime/msvcp140_1.dll', 'search/runtime/onnxruntime_providers_shared.dll', 'search/runtime/onnxruntime.dll',
        'search/runtime/LICENSE', 'search/runtime/ThirdPartyNotices.txt')
    foreach ($set in @(@{ expected = $expectedBinaries; actual = @($provenance.binaries) },
        @{ expected = $expectedResources; actual = @($provenance.resources) })) {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($set.actual.Count -ne $set.expected.Count) { throw 'Candidate installed payload inventory differs.' }
        foreach ($record in $set.actual) {
            if ($record.name -cnotin $set.expected -or -not $seen.Add($record.name)) { throw 'Unexpected or duplicate installed payload record.' }
            $null = Assert-FileRecord $installRoot $record
        }
    }
    $script:evidence.stages.installedPayload = [ordered]@{ binaries = $expectedBinaries.Count; resources = $expectedResources.Count; result = 'passed' }
    $script:evidence.installDirectory = $installRoot
    $daemonPath = Join-Path $installRoot 'context-relay-contextd.exe'
    $bridgePath = Join-Path $installRoot 'context-relay-context-mcp.exe'
    # Closed input proves both shipped helper executables load and reject an
    # absent request before admitting a stage or native mutation. Not scanner qualification.
    foreach ($name in @('context-relay-native-helper.exe', 'context-relay-sidecar-installer.exe')) {
        Complete-Process (Start-OwnedProcess (Join-Path $installRoot $name)) 10 2
    }
    $script:evidence.stages.helperLoadAndRefusal = 'passed'
    $desktop = Start-OwnedProcess (Join-Path $installRoot 'context-relay-desktop.exe') @() $true
    Wait-VisibleElement $desktop 'Choose harnesses' 60
    Wait-VisibleElement $desktop 'Finish later' 10 $true
    Wait-VisibleElement $desktop 'Ready on this computer' 60
    $daemon = Capture-InstalledDaemon $daemonPath
    $script:evidence.stages.desktopReady = [ordered]@{ result = 'passed'; desktopPid = $desktop.Process.Id; daemonPid = $daemon.Process.Id }
    Wait-VisibleElement $desktop 'Context' 10 $true
    Wait-VisibleElement $desktop 'Search is ready.' 120
    $script:evidence.stages.packagedSearch = [ordered]@{ result = 'passed'; visibleText = 'Search is ready.'; scope = 'model/runtime initialization with an empty vault' }
    $script:evidence.stages.installedMcp = Test-InstalledMcp $bridgePath $provenance.version
    Close-Desktop $desktop
    Stop-InstalledDaemon $daemonPath
    $script:evidence.stages.bridgeColdStart = Test-InstalledMcp $bridgePath $provenance.version
    $null = Capture-InstalledDaemon $daemonPath
    Stop-InstalledDaemon $daemonPath
    if (-not (Test-Path -LiteralPath $vaultPath -PathType Leaf)) { throw 'Production first launch did not create its expected vault.' }
    $script:evidence.result = 'passed'
} catch {
    $failure = $_.Exception.Message
    $script:evidence.result = 'failed'
    $script:evidence.failure = $failure
} finally {
    try { Close-Desktop $desktop } catch { $script:evidence.cleanup.desktop = $_.Exception.Message; $script:evidence.result = 'failed' }
    # Use authenticated shutdown before any forced cleanup of captured objects.
    if ($daemonPath -and (Test-Path -LiteralPath $daemonPath)) {
        try { Stop-InstalledDaemon $daemonPath; $script:evidence.cleanup.daemon = 'stopped' }
        catch { $script:evidence.cleanup.daemon = $_.Exception.Message; $script:evidence.result = 'failed' }
    }
    if ($uninstaller) {
        try {
            Assert-RegularPath $uninstaller.path
            if ((Get-FileHash -LiteralPath $uninstaller.path -Algorithm SHA256).Hash -cne $uninstaller.sha256) {
                throw 'Installed uninstaller changed before cleanup.'
            }
            $retainedVault = $null
            if (Test-Path -LiteralPath $vaultPath -PathType Leaf) {
                Assert-RegularPath $vaultPath
                $retainedVault = [ordered]@{ bytes = (Get-Item -LiteralPath $vaultPath).Length
                    sha256 = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash }
            }
            Complete-Process (Start-OwnedProcess $uninstaller.path @('/S')) 120
            $deadline = [DateTime]::UtcNow.AddSeconds(60)
            do {
                $remaining = @(Get-ProductEntries)
                $installedFiles = @($expectedBinaries | Where-Object { Test-Path -LiteralPath (Join-Path $installRoot $_) })
                if ($remaining.Count -eq 0 -and $installedFiles.Count -eq 0) { break }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $deadline)
            if ($remaining.Count -ne 0 -or $installedFiles.Count -ne 0) { throw 'Installed files or registration survived uninstall.' }
            if ($retainedVault) {
                Assert-RegularPath $vaultPath
                if ((Get-Item -LiteralPath $vaultPath).Length -ne $retainedVault.bytes -or
                    (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash -cne $retainedVault.sha256) {
                    throw 'Uninstall changed the retained vault bytes.'
                }
            }
            $script:evidence.cleanup.uninstall = [ordered]@{ result = 'passed'; path = $uninstaller.path; sha256 = $uninstaller.sha256
                retainedVaultBytesUnchanged = ($null -ne $retainedVault) }
        } catch {
            $script:evidence.cleanup.uninstall = $_.Exception.Message
            $script:evidence.result = 'failed'
        }
    }
    # Keep ownership until AFTER uninstall: NSIS self-copy, WebView children,
    # and a daemon that failed before status/capture all remain in this job.
    if ($script:processJob) {
        try {
            if (-not $script:processJob.WaitForEmpty(10000)) {
                $script:evidence.forcedCleanup = $true
                $script:evidence.result = 'failed'
                try {
                    $script:evidence.cleanup.remainingOwnedImages = @($script:processJob.GetProcesses() | ForEach-Object {
                        try { [ordered]@{ processId = $_.Id; path = $_.MainModule.FileName } }
                        finally { $_.Dispose() }
                    })
                } finally { $script:processJob.Terminate() }
                if (-not $script:processJob.WaitForEmpty(10000)) { throw 'Owned process tree did not stop within its cleanup deadline.' }
            }
            $script:evidence.cleanup.processJob = 'empty'
        } catch {
            $script:evidence.cleanup.processJob = $_.Exception.Message
            $script:evidence.result = 'failed'
        } finally {
            # KILL_ON_JOB_CLOSE also covers driver exceptions and runner cancellation.
            $script:processJob.Dispose()
        }
    }
    try { $script:evidence.webViewAfter = Get-WebViewObservation }
    catch { $script:evidence.cleanup.webViewObservation = $_.Exception.Message; $script:evidence.result = 'failed' }
    $script:evidence.finishedAt = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'installed-smoke.json'),
        (ConvertTo-Json -InputObject $script:evidence -Depth 16), [Text.UTF8Encoding]::new($false))
}
if ($script:evidence.result -ne 'passed') { throw 'Installed Windows smoke failed; inspect the bounded installed-smoke.json evidence.' }
Write-Host 'Installed Windows smoke passed: rendered UI, packaged search, authenticated MCP, cold start, and uninstall.'
