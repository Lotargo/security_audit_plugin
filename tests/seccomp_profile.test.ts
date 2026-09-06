import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { findSandboxSeccompProfile } from '../src/docker/runner.js';

type SeccompRule = {
  names?: string[];
  action?: string;
  includes?: { caps?: string[] };
};

describe('Evolve bubblewrap seccomp profile', () => {
  it('keeps an ERRNO-by-default allowlist and gates pivot_root behind CAP_SYS_ADMIN', () => {
    const profilePath = findSandboxSeccompProfile();
    expect(profilePath).not.toBeNull();

    const profile = JSON.parse(readFileSync(profilePath!, 'utf8')) as {
      defaultAction?: string;
      syscalls?: SeccompRule[];
    };

    expect(profile.defaultAction).toBe('SCMP_ACT_ERRNO');

    const pivotRules = (profile.syscalls || []).filter((rule) =>
      rule.names?.includes('pivot_root')
    );
    expect(pivotRules).toHaveLength(1);
    expect(pivotRules[0].action).toBe('SCMP_ACT_ALLOW');
    expect(pivotRules[0].includes?.caps).toContain('CAP_SYS_ADMIN');

    expect(pivotRules[0].names).toEqual(
      expect.arrayContaining(['clone', 'mount', 'pivot_root', 'sethostname', 'umount2'])
    );

    for (const forbidden of [
      'bpf',
      'fanotify_init',
      'lookup_dcookie',
      'perf_event_open',
      'quotactl',
      'syslog',
    ]) {
      expect(pivotRules[0].names).not.toContain(forbidden);
    }
  });
});
