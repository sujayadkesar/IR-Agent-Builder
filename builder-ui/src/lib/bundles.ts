import type { Bundle } from './types';

// Mirror of the backend bundles, used for the eager initial render before
// the API call resolves. The real source of truth is /api/bundles.
export const FALLBACK_BUNDLES: Bundle[] = [
  // Windows bundles
  {
    id: 'QuickTriage',
    name: 'Quick Triage',
    estimateLabel: '5-15 min · ~200 MB',
    color: 'emerald',
    description: 'Rapid triage — execution, persistence, live network. Safe for live production servers.',
    artifacts: [],
    kapeTargets: [],
    platform: 'windows',
  },
  {
    id: 'SANSTriage',
    name: 'SANS / KAPE Triage',
    estimateLabel: '30-60 min · 1-3 GB',
    color: 'blue',
    description: 'KAPE SANS Triage equivalent. Adds full Registry, EVTX, browser, jump lists, RDP cache.',
    artifacts: [],
    kapeTargets: [],
    platform: 'windows',
  },
  {
    id: 'DeepDive',
    name: 'Deep Dive',
    estimateLabel: '1-4 hr · 5-20 GB',
    color: 'purple',
    description: 'Everything: full MFT/USN, all EVTX, full RAM dump, full browser, Outlook OST/PST.',
    artifacts: [],
    kapeTargets: [],
    platform: 'windows',
  },
  {
    id: 'ThreatHunt',
    name: 'Threat Hunt',
    estimateLabel: '15-30 min · ~500 MB',
    color: 'amber',
    description: 'Targeted hunt for active TTPs — live network, persistence, lateral movement evidence.',
    artifacts: [],
    kapeTargets: [],
    platform: 'windows',
  },
  // Linux bundles
  {
    id: 'LinuxQuickTriage',
    name: 'Linux Quick Triage',
    estimateLabel: '2-5 min · ~50 MB',
    color: 'emerald',
    description: 'Fast Linux triage — processes, connections, users, system info, auth logs.',
    artifacts: [],
    kapeTargets: [],
    platform: 'linux',
  },
  {
    id: 'LinuxFullTriage',
    name: 'Linux Full Triage',
    estimateLabel: '10-30 min · 200 MB-1 GB',
    color: 'blue',
    description: 'Complete Linux collection — all logs, persistence, containers, browser, SSH keys, proc maps.',
    artifacts: [],
    kapeTargets: [],
    platform: 'linux',
  },
  {
    id: 'LinuxThreatHunt',
    name: 'Linux Threat Hunt',
    estimateLabel: '5-15 min · ~100 MB',
    color: 'red',
    description: 'Targeted Linux hunt — proc maps, crontabs, systemd units, audit rules, kernel modules, containers.',
    artifacts: [],
    kapeTargets: [],
    platform: 'linux',
  },
];
