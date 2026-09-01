import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
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

export async function runInstallSkills(options: { target: string; path?: string }): Promise<void> {
  const sourceSkillsDir = path.resolve(process.cwd(), 'skills');
  if (!fs.existsSync(sourceSkillsDir)) {
    throw new Error(`Source skills directory not found at: ${sourceSkillsDir}`);
  }

  let destinationDir: string;

  switch (options.target.toLowerCase()) {
    case 'agy':
    case 'antigravity':
      destinationDir = path.join(os.homedir(), '.gemini', 'config', 'plugins', 'security-audit', 'skills');
      break;
    case 'local-agents':
      destinationDir = path.resolve(process.cwd(), '.agents', 'skills');
      break;
    case 'opencode':
      destinationDir = path.resolve(process.cwd(), '.opencode', 'skills');
      break;
    case 'claude':
    case 'claude-code':
      destinationDir = path.resolve(process.cwd(), '.claude', 'skills');
      break;
    case 'custom':
      if (!options.path) {
        throw new Error('Option --path is required when --target is "custom"');
      }
      destinationDir = path.resolve(options.path);
      break;
    default:
      destinationDir = path.resolve(process.cwd(), '.agents', 'skills');
      break;
  }

  console.log(bold(cyan(`\nInstalling 19 Security Audit Skills to: ${destinationDir}\n`)));

  if (!fs.existsSync(destinationDir)) {
    fs.mkdirSync(destinationDir, { recursive: true });
  }

  const skillDirs = fs.readdirSync(sourceSkillsDir).filter((d) => fs.statSync(path.join(sourceSkillsDir, d)).isDirectory());

  for (const skillName of skillDirs) {
    const srcPath = path.join(sourceSkillsDir, skillName);
    const destPath = path.join(destinationDir, skillName);
    copyRecursiveSync(srcPath, destPath);
    console.log(` ${green('✔')} [Skill] ${bold(skillName)} -> ${gray(destPath)}`);
  }

  console.log(bold(green(`\n✔ Successfully installed ${skillDirs.length} skills into ${destinationDir}\n`)));
}
