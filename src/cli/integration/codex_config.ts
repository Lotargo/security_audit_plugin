export const DEFAULT_CODEX_STARTUP_TIMEOUT_SEC = 60;
export const CODEX_SERVER_NAME = 'security-audit-sandbox';

export function escapeTomlBasicString(value: string): string {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\u0008/g, '\\b')
    .replace(/\t/g, '\\t')
    .replace(/\n/g, '\\n')
    .replace(/\f/g, '\\f')
    .replace(/\r/g, '\\r');
}

export function buildCodexSecurityAuditSection({
  nodePath,
  launcherPath,
  startupTimeoutSec = DEFAULT_CODEX_STARTUP_TIMEOUT_SEC,
}: {
  nodePath: string;
  launcherPath: string;
  startupTimeoutSec?: number;
}): string {
  if (!nodePath || !launcherPath) throw new Error('nodePath and launcherPath are required');
  if (!Number.isInteger(startupTimeoutSec) || startupTimeoutSec <= 0) {
    throw new Error('startupTimeoutSec must be a positive integer');
  }
  return [
    `[mcp_servers.${CODEX_SERVER_NAME}]`,
    `command = "${escapeTomlBasicString(nodePath)}"`,
    `args = ["${escapeTomlBasicString(launcherPath)}", "mcp"]`,
    `startup_timeout_sec = ${startupTimeoutSec}`,
  ].join('\n');
}

interface SectionRange {
  start: number;
  end: number;
  name: string;
}

function tableHeaderName(line: string): string | null {
  const match = String(line).match(/^\s*\[\s*([^\[\]]+?)\s*\]\s*(?:#.*)?$/);
  return match ? match[1] : null;
}

function isSecurityAuditHeader(name: string | null, exact = false): boolean {
  if (!name) return false;
  const suffix = exact ? '$' : '(?:\\s*\\.|$)';
  return new RegExp(
    `^mcp_servers\\s*\\.\\s*(?:${CODEX_SERVER_NAME}|"${CODEX_SERVER_NAME}"|'${CODEX_SERVER_NAME}')${suffix}`,
    'i'
  ).test(name);
}

export function isSecurityAuditOwnedCodexSection(sectionText: string): boolean {
  const text = String(sectionText || '').replace(/\\/g, '/');
  return /@security-audit\/plugin|security[_-]audit[_-]plugin|\/bin\/cli\.js/i.test(text)
    && /\bmcp\b/i.test(text);
}

function sectionRanges(lines: string[]): SectionRange[] {
  const headers: Array<{ start: number; name: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const name = tableHeaderName(lines[i]);
    if (name) headers.push({ start: i, name });
  }
  return headers.map((header, index) => ({
    ...header,
    end: index + 1 < headers.length ? headers[index + 1].start : lines.length,
  }));
}

function validateOwnedTargets(lines: string[], ranges: SectionRange[]) {
  const targets = ranges.filter((range) => isSecurityAuditHeader(range.name));
  if (targets.length === 0) return { targets, conflict: null as string | null };

  const exactTargets = targets.filter((range) => isSecurityAuditHeader(range.name, true));
  if (exactTargets.length !== 1) {
    return {
      targets,
      conflict: `Expected exactly one [mcp_servers.${CODEX_SERVER_NAME}] section`,
    };
  }

  const unowned = exactTargets.filter((range) => {
    const text = lines.slice(range.start, range.end).join('\n');
    return !isSecurityAuditOwnedCodexSection(text);
  });
  if (unowned.length > 0) {
    return {
      targets,
      conflict: `Existing [mcp_servers.${CODEX_SERVER_NAME}] section is not owned by @security-audit/plugin`,
    };
  }

  return { targets, conflict: null as string | null };
}

export function getCodexSecurityAuditSections(content: string) {
  const lines = String(content || '').split(/\r?\n/);
  return sectionRanges(lines)
    .filter((range) => isSecurityAuditHeader(range.name))
    .map((range) => ({
      ...range,
      exact: isSecurityAuditHeader(range.name, true),
      text: lines.slice(range.start, range.end).join('\n').trimEnd(),
    }));
}

export function updateCodexSecurityAuditConfig(
  content: string,
  options: { nodePath: string; launcherPath: string; startupTimeoutSec?: number }
) {
  const source = String(content || '');
  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  const lines = source.split(/\r?\n/);
  const desired = buildCodexSecurityAuditSection(options).split('\n');
  const ranges = sectionRanges(lines);
  const { targets, conflict } = validateOwnedTargets(lines, ranges);

  if (conflict) {
    return { content: source, changed: false, status: 'conflict' as const, reason: conflict };
  }

  if (targets.length === 0) {
    const prefix = source.length === 0 ? '' : source.replace(/[\r\n]+$/, '') + eol + eol;
    return {
      content: prefix + desired.join(eol) + eol,
      changed: true,
      status: 'added' as const,
    };
  }

  const targetLineIndexes = new Set<number>();
  for (const target of targets) {
    for (let i = target.start; i < target.end; i++) targetLineIndexes.add(i);
  }

  const firstStart = Math.min(...targets.map((target) => target.start));
  const result: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (i === firstStart) {
      while (result.length > 0 && result[result.length - 1] === '') result.pop();
      if (result.length > 0) result.push('');
      result.push(...desired, '');
    }
    if (targetLineIndexes.has(i)) continue;
    result.push(lines[i]);
  }

  while (result.length > 1 && result[result.length - 1] === '' && result[result.length - 2] === '') {
    result.pop();
  }
  const updated = result.join(eol);
  return {
    content: updated,
    changed: updated !== source,
    status: updated === source ? ('unchanged' as const) : ('migrated' as const),
  };
}

export function removeCodexSecurityAuditConfig(content: string) {
  const source = String(content || '');
  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  const lines = source.split(/\r?\n/);
  const ranges = sectionRanges(lines);
  const { targets, conflict } = validateOwnedTargets(lines, ranges);

  if (targets.length === 0) {
    return { content: source, changed: false, status: 'not_found' as const, removed: 0 };
  }
  if (conflict) {
    return {
      content: source,
      changed: false,
      status: 'conflict' as const,
      reason: conflict,
      removed: 0,
    };
  }

  const targetLineIndexes = new Set<number>();
  for (const target of targets) {
    let contentEnd = target.end;
    while (contentEnd > target.start + 1 && lines[contentEnd - 1] === '') contentEnd--;
    for (let i = target.start; i < contentEnd; i++) targetLineIndexes.add(i);
  }

  const result = lines.filter((_, index) => !targetLineIndexes.has(index));
  let updated = result.join(eol);
  if (updated.trim() === '') updated = '';
  return {
    content: updated,
    changed: updated !== source,
    status: updated !== source ? ('removed' as const) : ('unchanged' as const),
    removed: targets.length,
  };
}
