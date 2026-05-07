import type { Bundle } from './types';

// Mirror of the backend bundles, used for the eager initial render before
// the API call resolves. The real source of truth is /api/bundles.
export const FALLBACK_BUNDLES: Bundle[] = [
  {
    id: 'QuickTriage',
    name: 'Quick Triage',
    estimateLabel: '5-15 min · ~200 MB',
    color: 'emerald',
    description: 'Rapid triage — execution, persistence, live network. Safe for live production servers.',
    artifacts: [],
    kapeTargets: [],
  },
  {
    id: 'SANSTriage',
    name: 'SANS / KAPE Triage',
    estimateLabel: '30-60 min · 1-3 GB',
    color: 'blue',
    description: 'KAPE SANS Triage equivalent. Adds full Registry, EVTX, browser, jump lists, RDP cache.',
    artifacts: [],
    kapeTargets: [],
  },
  {
    id: 'DeepDive',
    name: 'Deep Dive',
    estimateLabel: '1-4 hr · 5-20 GB',
    color: 'purple',
    description: 'Everything: full MFT/USN, all EVTX, full RAM dump, full browser, Outlook OST/PST.',
    artifacts: [],
    kapeTargets: [],
  },
  {
    id: 'ThreatHunt',
    name: 'Threat Hunt',
    estimateLabel: '15-30 min · ~500 MB',
    color: 'amber',
    description: 'Targeted hunt for active TTPs — live network, persistence, lateral movement evidence.',
    artifacts: [],
    kapeTargets: [],
  },
];
