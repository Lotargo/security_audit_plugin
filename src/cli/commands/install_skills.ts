import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { green, bold, cyan, yellow, gray } from 'colorette';

function copyRecursiveSync(src: string, dest: string) {
  const exists = fs.existsSync(src);
  const stats = exists && fs.statSync(src);
  const isDirectory = exists && stats && stats.isDirectory();
  if (isDirectory) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }
    fs.readdirSync(src).forEach((childItemName) => {
      copyRecursiveSync(path.join(src, childItemName), path.join(dest, childItemName));
    });
  } else {
    fs.copyFileSync(src, dest);
  }
}

export function findSourceSkillsDir(): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));

  const candidates = [
    // 1. From dist/src/cli/commands/ (npm package installed)
    path.resolve(currentDir, '../../../../skills'),
    // 2. From src/cli/commands/ (dev ts-node / vitest)
    path.resolve(currentDir, '../../../skills'),
    // 3. Fallback to process.cwd()/skills
    path.resolve(process.cwd(), 'skills'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      return candidate;
    }
  }

  throw new Error(`Source skills directory not found in package candidates: ${candidates.join(', ')}`);
}

export function resolveDestinationDirs(target: string, customPath?: string): string[] {
  const t = target.toLowerCase();

  if (t === 'all') {
    return [
      path.join(os.homedir(), '.gemini', 'config', 'plugins', 'security-audit', 'skills'),
      path.resolve(process.cwd(), '.agents', 'skills'),
      path.resolve(process.cwd(), '.opencode', 'skills'),
      path.resolve(process.cwd(), '.claude', 'skills'),
    ];
  }

  switch (t) {
    case 'agy':
    case 'antigravity':
      return [path.join(os.homedir(), '.gemini', 'config', 'plugins', 'security-audit', 'skills')];
    case 'local-agents':
    case 'local':
      return [path.resolve(process.cwd(), '.agents', 'skills')];
    case 'opencode':
      return [path.resolve(process.cwd(), '.opencode', 'skills')];
    case 'claude':
    case 'claude-code':
      return [path.resolve(process.cwd(), '.claude', 'skills')];
    case 'custom':
      if (!customPath) {
        throw new Error('Option --path is required when --target is "custom"');
      }
      return [path.resolve(customPath)];
    default:
      return [path.resolve(process.cwd(), '.agents', 'skills')];
  }
}

export async function runInstallSkills(options: {
  target: string;
  path?: string;
  skills?: string[] | string;
  mcp?: boolean;
}): Promise<void> {
  const sourceSkillsDir = findSourceSkillsDir();
  const destinationDirs = resolveDestinationDirs(options.target, options.path);

  const allAvailableSkills = fs
    .readdirSync(sourceSkillsDir)
    .filter((d) => fs.statSync(path.join(sourceSkillsDir, d)).isDirectory());

  let selectedSkills: string[] = allAvailableSkills;

  if (options.skills) {
    const rawSkills = Array.isArray(options.skills) ? options.skills : options.skills.split(',');
    const filtered = rawSkills.map((s) => s.trim()).filter(Boolean);
    if (filtered.length > 0 && !filtered.includes('all')) {
      selectedSkills = allAvailableSkills.filter((s) => filtered.includes(s));
      if (selectedSkills.length === 0) {
        throw new Error(
          `None of the requested skills (${filtered.join(', ')}) were found in available skills.`
        );
      }
    }
  }

  for (const destinationDir of destinationDirs) {
    console.log(bold(cyan(`\nInstalling ${selectedSkills.length} Security Audit Skills to: ${destinationDir}\n`)));

    if (!fs.existsSync(destinationDir)) {
      fs.mkdirSync(destinationDir, { recursive: true });
    }

    for (const skillName of selectedSkills) {
      const srcPath = path.join(sourceSkillsDir, skillName);
      const destPath = path.join(destinationDir, skillName);
      copyRecursiveSync(srcPath, destPath);
      console.log(` ${green('✔')} [Skill] ${bold(skillName)} -> ${gray(destPath)}`);
    }

    console.log(bold(green(`\n✔ Successfully installed ${selectedSkills.length} skills into ${destinationDir}`)));
  }

  if (options.mcp) {
    console.log(bold(cyan('\n--- MCP Server Configuration Snippet ---')));
    console.log(
      JSON.stringify(
        {
          mcpServers: {
            'security-audit-sandbox': {
              command: 'npx',
              args: ['-y', '@security-audit/plugin', 'mcp'],
            },
          },
        },
        null,
        2
      )
    );
    console.log(gray('Add the snippet above to your agent MCP configuration file.\n'));
  }
}
