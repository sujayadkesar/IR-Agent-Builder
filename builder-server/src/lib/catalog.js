// Artifact catalog & bundle presets — the master list shown to the UI.
//
// Each artifact entry must mirror the dispatcher in collector/src/artifacts/mod.rs.
// `id` is the canonical name passed to the collector via embedded_config.json.
// `sizeMb` and `timeSec` are rough estimates used for the live "running totals"
// in the wizard. They're conservative averages — actual collection time depends
// on endpoint specs and disk size.
//
// `params` is OPTIONAL per-artifact customization. When present, the UI shows
// inline controls under the artifact row, and the user's selection is passed
// through to the collector via `artifact_params[<id>]`. Each param is one of:
//
//   { key, label, type: 'select', default, options: [{ value, label, desc?, sizeMul? }] }
//   { key, label, type: 'number', default, min?, max?, step?, suffix? }
//   { key, label, type: 'boolean', default }
//
// `sizeMul` on a select option scales the artifact's `sizeMb` estimate when
// that option is chosen — so the live size totals stay accurate.

// ---------- Reusable parameter definitions ----------

const BROWSER_SCOPE_PARAM = {
  key: 'scope',
  label: 'Collection scope',
  type: 'select',
  default: 'standard',
  options: [
    { value: 'minimal',  label: 'History only',                 desc: 'Just History DB per profile (~10–50 MB). Fastest, smallest.', sizeMul: 0.25 },
    { value: 'standard', label: 'Standard forensic set',        desc: 'History, Cookies, Login Data, Web Data, Bookmarks, Sessions, Top Sites, Shortcuts.', sizeMul: 1.0 },
    { value: 'full',     label: 'Full User Data folder',        desc: 'Everything: extensions, IndexedDB, cache, profile pictures, sync data. Large.', sizeMul: 10.0 },
  ],
};

const BROWSER_PROFILE_PARAM = {
  key: 'profiles',
  label: 'Which profiles',
  type: 'select',
  default: 'all',
  options: [
    { value: 'default', label: 'Default profile only',        desc: '"Default" subfolder only (the common case).', sizeMul: 0.5 },
    { value: 'all',     label: 'All profiles',                desc: 'Default + Profile 1, Profile 2, ... Comprehensive but larger.', sizeMul: 1.0 },
  ],
};

// Firefox uses a different layout (no profile subdirectory pattern), so its
// scope param is simpler.
const BROWSER_SCOPE_PARAM_FIREFOX = {
  key: 'scope',
  label: 'Collection scope',
  type: 'select',
  default: 'standard',
  options: [
    { value: 'minimal',  label: 'places.sqlite only',           desc: 'History DB only.', sizeMul: 0.3 },
    { value: 'standard', label: 'Standard forensic set',        desc: 'places + cookies + formhistory + downloads + logins.', sizeMul: 1.0 },
    { value: 'full',     label: 'Full Profiles folder',         desc: 'Everything in Profiles\\*.default-release including cache.', sizeMul: 8.0 },
  ],
};

const EVTX_SCOPE_PARAM = {
  key: 'scope',
  label: 'Time range',
  type: 'select',
  default: 'all',
  options: [
    { value: 'all',       label: 'Whole .evtx file',  desc: 'Complete log (most thorough). Default.', sizeMul: 1.0 },
    { value: 'last_30d',  label: 'Last 30 days',      desc: 'Filter on collection-side via wevtutil. Smaller container.', sizeMul: 0.4 },
    { value: 'last_7d',   label: 'Last 7 days',       desc: 'Recent-incident triage.', sizeMul: 0.15 },
  ],
};

export const ARTIFACT_CATALOG = [
  {
    category: 'Evidence of Execution',
    items: [
      { id: 'execution.prefetch',  name: 'Prefetch',          desc: 'Binary execution times, file paths, run counts (Windows/Prefetch/*.pf)',                  sizeMb: 30,   timeSec: 15, deps: ['ADMIN'] },
      { id: 'execution.amcache',   name: 'Amcache',           desc: 'First-execution record + SHA1 hash of every executable that has run',                       sizeMb: 25,   timeSec: 10, deps: ['ADMIN'] },
      { id: 'execution.shimcache', name: 'AppCompatCache',    desc: 'Historical execution evidence (lives in SYSTEM hive — collected with Registry too)',        sizeMb: 5,    timeSec: 5,  deps: ['ADMIN'] },
      { id: 'execution.bam',       name: 'BAM/DAM',           desc: 'Per-user binary execution attribution',                                                     sizeMb: 1,    timeSec: 2,  deps: ['ADMIN'] },
      { id: 'execution.userassist',name: 'UserAssist',        desc: 'GUI program launch counts via Explorer (NTUSER.DAT)',                                       sizeMb: 1,    timeSec: 2,  deps: ['ADMIN'] },
      { id: 'execution.muicache',  name: 'MUICache',          desc: 'Historical GUI program names — survives Prefetch clears',                                   sizeMb: 1,    timeSec: 2,  deps: ['ADMIN'] },
    ],
  },
  {
    category: 'File System',
    items: [
      { id: 'filesystem.mft',         name: 'MFT + LogFile + USN', desc: 'Master File Table, transaction log, USN journal — foundational filesystem evidence',       sizeMb: 800,  timeSec: 90,  deps: ['ADMIN', 'VSS'] },
      { id: 'filesystem.lnk',         name: 'LNK + Jump Lists',    desc: 'Shortcut metadata + Jump Lists — proves file access including network shares',             sizeMb: 25,   timeSec: 10,  deps: ['ADMIN'] },
      { id: 'filesystem.recyclebin',  name: 'Recycle Bin',         desc: 'Deleted file metadata: original path, deletion time, size',                                sizeMb: 15,   timeSec: 5,   deps: ['ADMIN'] },
    ],
  },
  {
    category: 'Registry',
    items: [
      { id: 'registry.hives', name: 'All Registry Hives',  desc: 'SAM/SECURITY/SOFTWARE/SYSTEM/DEFAULT + per-user NTUSER.DAT and UsrClass.dat (with .LOG1/.LOG2)', sizeMb: 250, timeSec: 30, deps: ['ADMIN', 'VSS'] },
    ],
  },
  {
    category: 'Event Logs',
    items: [
      { id: 'eventlogs.security',      name: 'Security.evtx',         desc: 'Logon/logoff (4624/4634), privilege use, account management',                             sizeMb: 200, timeSec: 25, deps: ['ADMIN'], params: [EVTX_SCOPE_PARAM] },
      { id: 'eventlogs.system',        name: 'System.evtx',           desc: 'Service installs, driver loads, crashes, startup/shutdown',                                sizeMb: 50,  timeSec: 15, deps: ['ADMIN'], params: [EVTX_SCOPE_PARAM] },
      { id: 'eventlogs.application',   name: 'Application.evtx',      desc: 'Application errors, crashes, AV events',                                                  sizeMb: 30,  timeSec: 10, deps: ['ADMIN'], params: [EVTX_SCOPE_PARAM] },
      { id: 'eventlogs.powershell',    name: 'PowerShell logs',       desc: 'Script block (4104), module logging, transcripts',                                        sizeMb: 100, timeSec: 20, deps: ['ADMIN'] },
      { id: 'eventlogs.sysmon',        name: 'Sysmon (if installed)', desc: 'Process create, network, file writes, registry, DNS — the gold standard',                 sizeMb: 400, timeSec: 60, deps: ['ADMIN', 'SYSMON'] },
      { id: 'eventlogs.defender',      name: 'Windows Defender',      desc: 'Threat detections, exclusion changes, scan results',                                      sizeMb: 20,  timeSec: 10, deps: ['ADMIN'] },
      { id: 'eventlogs.rdp',           name: 'RDP logs',              desc: 'TerminalServices client/server connection events',                                        sizeMb: 15,  timeSec: 5,  deps: ['ADMIN'] },
      { id: 'eventlogs.taskscheduler', name: 'Task Scheduler',        desc: 'Task registration, execution, modification events',                                       sizeMb: 10,  timeSec: 5,  deps: ['ADMIN'] },
      { id: 'eventlogs.wmi',           name: 'WMI Activity',          desc: 'WMI process invocations, subscriptions',                                                  sizeMb: 10,  timeSec: 5,  deps: ['ADMIN'] },
      { id: 'eventlogs.bits',          name: 'BITS Activity',         desc: 'Background Intelligent Transfer Service jobs (LOLBin downloads)',                         sizeMb: 5,   timeSec: 3,  deps: ['ADMIN'] },
    ],
  },
  {
    category: 'Live Network & System',
    items: [
      { id: 'live.netstat',     name: 'Active connections', desc: 'netstat -anob — TCP/UDP with PIDs (run FIRST for live C2)',                       sizeMb: 1,  timeSec: 5,  deps: ['ADMIN'] },
      { id: 'live.pslist',      name: 'Process list',       desc: 'tasklist /v /fo csv — current processes with users and titles',                  sizeMb: 1,  timeSec: 3,  deps: ['ADMIN'] },
      { id: 'live.dnscache',    name: 'DNS cache',          desc: 'ipconfig /displaydns — cached resolutions reveal C2 domains',                    sizeMb: 1,  timeSec: 2,  deps: [] },
      { id: 'live.arpcache',    name: 'ARP cache',          desc: 'arp -a — current MAC↔IP table',                                                  sizeMb: 1,  timeSec: 1,  deps: [] },
      { id: 'live.services',    name: 'Services',           desc: 'sc query + wmic service get — enumerated services',                              sizeMb: 1,  timeSec: 5,  deps: [] },
      { id: 'live.systeminfo',  name: 'System info',        desc: 'systeminfo — OS, hotfixes, network adapters',                                    sizeMb: 1,  timeSec: 5,  deps: [] },
      { id: 'live.usbhistory',  name: 'USB history',        desc: 'reg query USBSTOR — connected USB device history',                               sizeMb: 1,  timeSec: 2,  deps: ['ADMIN'] },
      { id: 'live.wifihistory', name: 'WiFi history',       desc: 'netsh wlan show profiles — SSID history',                                        sizeMb: 1,  timeSec: 2,  deps: [] },
      { id: 'live.shares',      name: 'Network shares',     desc: 'net share — currently exposed shares',                                           sizeMb: 1,  timeSec: 1,  deps: [] },
      { id: 'live.firewallrules', name: 'Firewall rules',   desc: 'netsh advfirewall — every firewall rule on the host',                            sizeMb: 2,  timeSec: 5,  deps: ['ADMIN'] },
      { id: 'live.autoruns',    name: 'Autoruns',           desc: 'PowerShell sweep of HKLM/HKCU Run/RunOnce keys',                                 sizeMb: 1,  timeSec: 3,  deps: ['ADMIN'] },
    ],
  },
  {
    category: 'Persistence',
    items: [
      { id: 'persistence.scheduledtasks',  name: 'Scheduled Tasks (XML)', desc: 'Windows/System32/Tasks — every task definition with actions/triggers/principals', sizeMb: 5,   timeSec: 5,  deps: ['ADMIN'] },
      { id: 'persistence.startupfolders',  name: 'Startup folders',       desc: 'Per-user and system Start Menu Startup folders',                                  sizeMb: 1,   timeSec: 2,  deps: ['ADMIN'] },
    ],
  },
  {
    category: 'Browser',
    items: [
      {
        id: 'browser.chrome', name: 'Chrome',
        desc: 'Chrome / Chromium browser data — scope below controls how much is collected',
        sizeMb: 200, timeSec: 30, deps: ['ADMIN'],
        params: [BROWSER_SCOPE_PARAM, BROWSER_PROFILE_PARAM],
      },
      {
        id: 'browser.edge', name: 'Edge',
        desc: 'Microsoft Edge browser data',
        sizeMb: 100, timeSec: 20, deps: ['ADMIN'],
        params: [BROWSER_SCOPE_PARAM, BROWSER_PROFILE_PARAM],
      },
      {
        id: 'browser.firefox', name: 'Firefox',
        desc: 'Firefox browser data per profile',
        sizeMb: 100, timeSec: 20, deps: ['ADMIN'],
        params: [BROWSER_SCOPE_PARAM_FIREFOX],
      },
    ],
  },
  {
    category: 'Cloud & Modern',
    items: [
      { id: 'cloud.onedrive', name: 'OneDrive logs',     desc: 'OneDrive sync logs — exfiltration via personal cloud',                  sizeMb: 50, timeSec: 10, deps: ['ADMIN'] },
      { id: 'cloud.outlook',  name: 'Outlook PST/OST',   desc: 'Local mail data files (very large — disable if unwanted)',              sizeMb: 2000, timeSec: 120, deps: ['ADMIN'] },
      { id: 'cloud.teams',    name: 'Microsoft Teams',   desc: 'Teams cache — message DB, call logs, cached files',                     sizeMb: 200, timeSec: 30, deps: ['ADMIN'] },
      { id: 'cred.dpapi',     name: 'DPAPI master keys', desc: 'Windows DPAPI master keys + user credential blobs',                     sizeMb: 5, timeSec: 5, deps: ['ADMIN'] },
    ],
  },
  {
    category: 'Memory',
    items: [
      { id: 'memory.fulldump', name: 'Full RAM dump (winpmem)', desc: 'Full physical memory image via winpmem driver — 8-32GB output, requires winpmem.exe alongside collector', sizeMb: 16000, timeSec: 600, deps: ['ADMIN', 'WINPMEM'] },
    ],
  },
];

// KAPE-style targets that the user can layer on top of the artifact list.
export const KAPE_TARGETS = [
  'KapeTriage', 'EventLogs', 'Registry', 'Prefetch', 'WebBrowsers',
  'ScheduledTasks', 'StartupFolders', 'RecycleBin', 'BITS', 'WindowsFirewall',
  'RDPCache', 'PowerShellConsole', 'WindowsTimeline', 'JumpLists', 'LNKFiles',
  'SRUM', 'WinDefendDetectionHist', 'Outlook', 'DPAPI', 'CloudStorage_Metadata',
];

// Pre-baked bundles — the headline buttons in the UI (§2.10 of the research).
export const BUNDLES = [
  {
    id: 'QuickTriage',
    name: 'Quick Triage',
    estimateLabel: '5-15 min · ~200 MB',
    color: 'emerald',
    description: 'Rapid triage — execution, persistence, live network. Safe for live production servers.',
    artifacts: [
      'execution.prefetch', 'execution.amcache', 'execution.shimcache',
      'live.netstat', 'live.pslist', 'live.dnscache', 'live.systeminfo',
      'eventlogs.security', 'eventlogs.system', 'eventlogs.application',
      'persistence.scheduledtasks', 'live.autoruns',
      'live.usbhistory', 'live.wifihistory',
    ],
    kapeTargets: [],
  },
  {
    id: 'SANSTriage',
    name: 'SANS / KAPE Triage',
    estimateLabel: '30-60 min · 1-3 GB',
    color: 'blue',
    description: 'Equivalent of KAPE\'s SANS Triage Package. Adds full Registry, EVTX, browser, jump lists, RDP cache.',
    artifacts: [
      'execution.prefetch', 'execution.amcache', 'execution.shimcache', 'execution.userassist',
      'live.netstat', 'live.pslist', 'live.dnscache', 'live.arpcache', 'live.services', 'live.systeminfo',
      'live.usbhistory', 'live.wifihistory', 'live.shares', 'live.firewallrules', 'live.autoruns',
      'eventlogs.security', 'eventlogs.system', 'eventlogs.application',
      'eventlogs.powershell', 'eventlogs.defender', 'eventlogs.rdp',
      'eventlogs.taskscheduler', 'eventlogs.wmi', 'eventlogs.bits',
      'registry.hives',
      'filesystem.lnk', 'filesystem.recyclebin',
      'persistence.scheduledtasks', 'persistence.startupfolders',
      'browser.chrome', 'browser.edge', 'browser.firefox',
      'cloud.onedrive',
    ],
    kapeTargets: ['KapeTriage', 'EventLogs', 'Registry', 'Prefetch', 'WebBrowsers', 'JumpLists', 'LNKFiles', 'RDPCache', 'PowerShellConsole', 'WinDefendDetectionHist'],
  },
  {
    id: 'DeepDive',
    name: 'Deep Dive',
    estimateLabel: '1-4 hr · 5-20 GB',
    color: 'purple',
    description: 'Everything: full MFT/USN, all EVTX, full RAM dump, full browser, Outlook OST/PST. Requires storage headroom.',
    artifacts: [
      'execution.prefetch', 'execution.amcache', 'execution.shimcache', 'execution.userassist', 'execution.muicache', 'execution.bam',
      'live.netstat', 'live.pslist', 'live.dnscache', 'live.arpcache', 'live.services', 'live.systeminfo',
      'live.usbhistory', 'live.wifihistory', 'live.shares', 'live.firewallrules', 'live.autoruns',
      'eventlogs.security', 'eventlogs.system', 'eventlogs.application', 'eventlogs.powershell',
      'eventlogs.sysmon', 'eventlogs.defender', 'eventlogs.rdp', 'eventlogs.taskscheduler', 'eventlogs.wmi', 'eventlogs.bits',
      'registry.hives',
      'filesystem.mft', 'filesystem.lnk', 'filesystem.recyclebin',
      'persistence.scheduledtasks', 'persistence.startupfolders',
      'browser.chrome', 'browser.edge', 'browser.firefox',
      'cloud.onedrive', 'cloud.outlook', 'cloud.teams', 'cred.dpapi',
      'memory.fulldump',
    ],
    kapeTargets: ['KapeTriage', 'EventLogs', 'Registry', 'Prefetch', 'WebBrowsers', 'JumpLists', 'LNKFiles', 'RDPCache', 'PowerShellConsole', 'WinDefendDetectionHist', 'SRUM', 'WindowsTimeline', 'Outlook', 'DPAPI'],
  },
  {
    id: 'ThreatHunt',
    name: 'Threat Hunt',
    estimateLabel: '15-30 min · ~500 MB',
    color: 'amber',
    description: 'Targeted hunt for active TTPs — live network, persistence, lateral movement evidence. No memory dump.',
    artifacts: [
      'live.netstat', 'live.pslist', 'live.dnscache', 'live.arpcache', 'live.services', 'live.autoruns',
      'live.firewallrules', 'live.shares',
      'execution.prefetch', 'execution.amcache', 'execution.bam',
      'eventlogs.security', 'eventlogs.powershell', 'eventlogs.sysmon', 'eventlogs.taskscheduler', 'eventlogs.wmi', 'eventlogs.bits',
      'persistence.scheduledtasks', 'persistence.startupfolders',
      'registry.hives',
    ],
    kapeTargets: ['ScheduledTasks', 'StartupFolders', 'PowerShellConsole'],
  },
];
