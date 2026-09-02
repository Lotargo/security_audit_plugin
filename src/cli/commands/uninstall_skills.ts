import * as fs from 'node:fs';
import * as path from 'node:path';
import { green, yellow, bold, cyan, gray } from 'colorette';
import { resolveDestinationDirs, findSourceSkillsDir } from './install_skills.js';
import {
  clientsForInstallTarget,
  removeClientIntegrations,
} from '../integration/client_integration.js';

export async function runUninstallSkills(options: {
  target: string;
  path?: string;
  skills?: string[] | string;
  mcp?: boolean;
}): Promise<void> {
  let allKnownSkills: string[];
  try {
    const sourceDir = findSourceSkillsDir();
    allKnownSkills = fs
      .readdirSync(sourceDir)
      .filter((d) => fs.statSync(path.join(sourceDir, d)).isDirectory());
  } catch {
    allKnownSkills = [
      'security-audit-orchestrator',
      'tor-anonymity-onion-routing',
      'backend-topology-cartography',
      'web-appsec-dast',
      'abuse-prevention-resilience',
      'cryptography-token-security',
      'injection-input-validation',
      'access-control-business-logic',
      'client-supply-chain-magecart',
      'cloud-kubernetes-infra-audit',
      'data-exposure-privacy-resilience',
      'purple-team-detection-engineering',
      'http-smuggling-cache-attacks',
      'iam-active-directory-audit',
      'mobile-appsec-analysis',
      'network-segmentation-perimeter',
      'osint-attack-surface-mapping',
      'social-engineering-risk-assessment',
      'cicd-supply-chain-security',
    ];
  }

  const destinationDirs = resolveDestinationDirs(options.target, options.path);

  let targetSkills: string[] = allKnownSkills;
  if (options.skills) {
    const rawSkills = Array.isArray(options.skills) ? options.skills : options.skills.split(',');
    const filtered = rawSkills.map((s) => s.trim()).filter(Boolean);
    if (filtered.length > 0 && !filtered.includes('all')) {
      targetSkills = filtered;
    }
  }

  for (const destinationDir of destinationDirs) {
    console.log(bold(cyan(`\nUninstalling Security Audit Skills from: ${destinationDir}\n`)));

    if (!fs.existsSync(destinationDir)) {
      console.log(`${yellow('⚠')} Destination directory does not exist: ${gray(destinationDir)}`);
      continue;
    }

    let removedCount = 0;

    for (const skillName of targetSkills) {
      const skillPath = path.join(destinationDir, skillName);
      if (fs.existsSync(skillPath)) {
        fs.rmSync(skillPath, { recursive: true, force: true });
        console.log(` ${green('✔')} [Removed Skill] ${bold(skillName)} from ${gray(skillPath)}`);
        removedCount++;
      }
    }

    try {
      const remaining = fs.readdirSync(destinationDir);
      if (remaining.length === 0) {
        fs.rmdirSync(destinationDir);
        console.log(gray(` Cleaned up empty directory: ${destinationDir}`));
      }
    } catch {
      // Ignore cleanup error
    }

    console.log(bold(green(`\n✔ Successfully uninstalled ${removedCount} skills from ${destinationDir}`)));
  }

  if (options.mcp) {
    const clients = clientsForInstallTarget(options.target);
    if (clients.length > 0) {
      console.log(bold(cyan('\n--- Removing Owned MCP Client Registration(s) ---')));
      const results = await removeClientIntegrations({ clients });
      for (const result of results) {
        if (result.status === 'not_found') {
          console.log(` ${yellow('•')} ${bold(result.client)}: no owned registration found${result.path ? ` (${gray(result.path)})` : ''}`);
        } else {
          console.log(` ${green('✔')} ${bold(result.client)}: removed via ${result.method}${result.path ? ` (${gray(result.path)})` : ''}`);
          if (result.detail) console.log(gray(`   fallback detail: ${result.detail}`));
        }
      }
    } else {
      console.log(bold(yellow('\n[Note] This target has no managed client CLI registration to remove.\n')));
    }
  }
}
