import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runDoctor } from '../src/cli/commands/doctor.js';
import { runInstallSkills, findSourceSkillsDir } from '../src/cli/commands/install_skills.js';
import { runUninstallSkills } from '../src/cli/commands/uninstall_skills.js';

describe('CLI Commands Test Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-cli-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('doctor command', () => {
    it('executes system diagnostics without crashing and returns boolean', async () => {
      const isHealthy = await runDoctor();
      expect(typeof isHealthy).toBe('boolean');
    });
  });

  describe('findSourceSkillsDir', () => {
    it('successfully locates the skills directory in package or dev root', () => {
      const skillsDir = findSourceSkillsDir();
      expect(fs.existsSync(skillsDir)).toBe(true);
      const skills = fs.readdirSync(skillsDir);
      expect(skills).toContain('security-audit-orchestrator');
      expect(skills.length).toBe(19);
    });
  });

  describe('install-skills command', () => {
    it('installs all 19 skills into a custom directory', async () => {
      await runInstallSkills({ target: 'custom', path: tmpDir });

      const installed = fs
        .readdirSync(tmpDir)
        .filter((d) => fs.statSync(path.join(tmpDir, d)).isDirectory());

      expect(installed.length).toBe(19);
      expect(installed).toContain('security-audit-orchestrator');
      expect(installed).toContain('tor-anonymity-onion-routing');
      expect(installed).toContain('backend-topology-cartography');
      expect(installed).toContain('web-appsec-dast');

      // Verify SKILL.md exists in master skill
      const masterSkillMd = path.join(tmpDir, 'security-audit-orchestrator', 'SKILL.md');
      expect(fs.existsSync(masterSkillMd)).toBe(true);
      const content = fs.readFileSync(masterSkillMd, 'utf8');
      expect(content).toContain('name: security-audit-orchestrator');
    });

    it('installs selectively when --skills filter is provided', async () => {
      await runInstallSkills({
        target: 'custom',
        path: tmpDir,
        skills: 'web-appsec-dast,injection-input-validation',
        mcp: true,
      });

      const installed = fs
        .readdirSync(tmpDir)
        .filter((d) => fs.statSync(path.join(tmpDir, d)).isDirectory());

      expect(installed.length).toBe(2);
      expect(installed).toContain('web-appsec-dast');
      expect(installed).toContain('injection-input-validation');
      expect(installed).not.toContain('security-audit-orchestrator');
    });

    it('throws an error if custom target is missing path option', async () => {
      await expect(runInstallSkills({ target: 'custom' })).rejects.toThrow(
        'Option --path is required when --target is "custom"'
      );
    });

    it('throws an error if requested skills do not exist', async () => {
      await expect(
        runInstallSkills({
          target: 'custom',
          path: tmpDir,
          skills: 'non-existent-skill-xyz',
        })
      ).rejects.toThrow('None of the requested skills');
    });
  });

  describe('uninstall-skills command', () => {
    beforeEach(async () => {
      // Pre-install skills into tmpDir
      await runInstallSkills({ target: 'custom', path: tmpDir });
    });

    it('selectively uninstalls specified skills', async () => {
      expect(fs.existsSync(path.join(tmpDir, 'web-appsec-dast'))).toBe(true);
      expect(fs.existsSync(path.join(tmpDir, 'injection-input-validation'))).toBe(true);

      await runUninstallSkills({
        target: 'custom',
        path: tmpDir,
        skills: 'web-appsec-dast,injection-input-validation',
      });

      expect(fs.existsSync(path.join(tmpDir, 'web-appsec-dast'))).toBe(false);
      expect(fs.existsSync(path.join(tmpDir, 'injection-input-validation'))).toBe(false);
      // Other skills remain
      expect(fs.existsSync(path.join(tmpDir, 'security-audit-orchestrator'))).toBe(true);
    });

    it('uninstalls all skills and cleans up folder', async () => {
      await runUninstallSkills({
        target: 'custom',
        path: tmpDir,
        mcp: true,
      });

      // Destination directory should be cleaned up
      expect(fs.existsSync(tmpDir)).toBe(false);
    });
  });

  describe('findSandboxRuntimeDir & DockerRunner', () => {
    it('successfully locates bundled sandbox_runtime with Dockerfile', async () => {
      const { findSandboxRuntimeDir, DockerRunner } = await import('../src/docker/runner.js');
      const runtimeDir = findSandboxRuntimeDir();
      expect(runtimeDir).not.toBeNull();
      expect(fs.existsSync(path.join(runtimeDir!, 'Dockerfile'))).toBe(true);

      const runner = new DockerRunner();
      expect(typeof runner.isDockerAvailable).toBe('function');
      expect(typeof runner.isImageAvailable).toBe('function');
    });
  });
});
