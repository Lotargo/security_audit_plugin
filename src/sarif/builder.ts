import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  SarifLog,
  SarifRule,
  SarifResult,
  AuditFindingInput,
  SarifLocation,
} from './types.js';

/**
 * SarifReportBuilder compiles security audit findings into valid
 * OASIS SARIF v2.1.0 JSON documents and rich Markdown reports.
 */
export class SarifReportBuilder {
  private toolName: string = 'security-audit-plugin';
  private toolVersion: string = '0.4.0';
  private toolUri: string = 'https://github.com/Lotargo/security_audit_plugin';
  private rules: Map<string, SarifRule> = new Map();
  private results: SarifResult[] = [];
  private startTime: string = new Date().toISOString();

  constructor(options?: { toolName?: string; toolVersion?: string; toolUri?: string }) {
    if (options?.toolName) this.toolName = options.toolName;
    if (options?.toolVersion) this.toolVersion = options.toolVersion;
    if (options?.toolUri) this.toolUri = options.toolUri;
  }

  /**
   * Adds a pre-defined rule definition
   */
  public addRule(rule: SarifRule): this {
    this.rules.set(rule.id, rule);
    return this;
  }

  /**
   * Adds an audit finding with auto-registration of rule descriptor
   */
  public addFinding(finding: AuditFindingInput): this {
    // 1. Ensure rule is registered
    if (!this.rules.has(finding.ruleId)) {
      this.rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleName || finding.ruleId,
        shortDescription: { text: finding.ruleName || finding.ruleId },
        defaultConfiguration: { level: finding.level },
        properties: {
          tags: finding.tags || ['security', 'audit'],
          cwe: finding.cwe || [],
          owasp: finding.owasp || [],
          mitre: finding.mitre || [],
          cvssScore: finding.cvssScore,
          cvssVector: finding.cvssVector,
        },
      });
    }

    // 2. Build Location
    const locations: SarifLocation[] = [];
    if (finding.filePath || finding.endpointUri) {
      const uri = finding.filePath || finding.endpointUri || 'unknown';
      const loc: SarifLocation = {
        physicalLocation: {
          artifactLocation: {
            uri: uri.replace(/\\/g, '/'),
          },
        },
      };

      if (finding.startLine !== undefined) {
        loc.physicalLocation!.region = {
          startLine: finding.startLine,
          startColumn: finding.startColumn || 1,
          endLine: finding.endLine || finding.startLine,
          endColumn: finding.endColumn,
          snippet: finding.snippet ? { text: finding.snippet } : undefined,
        };
      }

      locations.push(loc);
    }

    // 3. Build Fixes
    const fixes = finding.fixes?.map((f) => ({
      description: { text: f.description },
      changes: [
        {
          artifactLocation: { uri: f.file.replace(/\\/g, '/') },
          replacements: [
            {
              deletedRegion: {
                startLine: f.startLine || 1,
                endLine: f.endLine || f.startLine || 1,
              },
              insertedContent: { text: f.replacement },
            },
          ],
        },
      ],
    }));

    // 4. Register Result
    const ruleIndex = Array.from(this.rules.keys()).indexOf(finding.ruleId);
    const result: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex: ruleIndex >= 0 ? ruleIndex : undefined,
      level: finding.level,
      message: {
        text: finding.message,
        markdown: finding.markdownMessage || finding.message,
      },
      locations: locations.length > 0 ? locations : undefined,
      fixes: fixes && fixes.length > 0 ? fixes : undefined,
      properties: {
        cvssScore: finding.cvssScore,
        cwe: finding.cwe,
        owasp: finding.owasp,
        mitre: finding.mitre,
        remediation: finding.remediation,
        remediationMarkdown: finding.remediationMarkdown,
        attackGraph: finding.attackGraph,
      } as any,
    };

    this.results.push(result);
    return this;
  }

  /**
   * Generates the compliant OASIS SARIF v2.1.0 Log object
   */
  public build(): SarifLog {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: this.toolName,
              version: this.toolVersion,
              informationUri: this.toolUri,
              rules: Array.from(this.rules.values()),
            },
          },
          invocations: [
            {
              executionSuccessful: true,
              startTimeUtc: this.startTime,
              endTimeUtc: new Date().toISOString(),
            },
          ],
          results: this.results,
        },
      ],
    };
  }

  /**
   * Exports SARIF as JSON string
   */
  public exportJson(pretty: boolean = true): string {
    return JSON.stringify(this.build(), null, pretty ? 2 : undefined);
  }

  /**
   * Saves SARIF report to file
   */
  public saveToFile(outputPath: string): void {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, this.exportJson(true), 'utf-8');
  }

  /**
   * Generates human-readable Markdown summary
   */
  public exportMarkdownSummary(): string {
    const errorCount = this.results.filter((r) => r.level === 'error').length;
    const warningCount = this.results.filter((r) => r.level === 'warning').length;
    const noteCount = this.results.filter((r) => r.level === 'note').length;
    const totalCount = this.results.length;

    let md = `# Security Audit Report\n\n`;
    md += `* **Generated by**: ${this.toolName} v${this.toolVersion}\n`;
    md += `* **Date**: ${new Date().toISOString()}\n`;
    md += `* **Total Findings**: ${totalCount} (🔴 Critical/High: ${errorCount}, 🟡 Medium/Low: ${warningCount}, 🔵 Informational: ${noteCount})\n\n`;

    md += `## 1. Executive Summary\n\n`;
    md += `| Severity | Count | Status |\n`;
    md += `| :--- | :--- | :--- |\n`;
    md += `| 🔴 Critical / High (\`error\`) | ${errorCount} | ${errorCount > 0 ? '⚠️ Action Required' : '✅ Clean'} |\n`;
    md += `| 🟡 Medium / Low (\`warning\`) | ${warningCount} | ${warningCount > 0 ? '⚠️ Review Needed' : '✅ Clean'} |\n`;
    md += `| 🔵 Informational (\`note\`) | ${noteCount} | ℹ️ Tracked |\n\n`;

    md += `## 2. Detailed Findings\n\n`;

    if (this.results.length === 0) {
      md += `> [!NOTE]\n> No security vulnerabilities or policy violations were detected in the target scope.\n\n`;
      return md;
    }

    for (let i = 0; i < this.results.length; i++) {
      const res = this.results[i];
      const rule = this.rules.get(res.ruleId);
      const icon = res.level === 'error' ? '🔴' : res.level === 'warning' ? '🟡' : '🔵';
      const loc = res.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri || 'N/A';
      const line = loc?.region?.startLine ? `:${loc.region.startLine}` : '';

      md += `### ${i + 1}. ${icon} [${res.ruleId}] ${rule?.name || res.ruleId}\n\n`;
      md += `- **Severity**: \`${res.level.toUpperCase()}\` ${res.properties?.cvssScore ? `(CVSS v3.1: **${res.properties.cvssScore}**)` : ''}\n`;
      md += `- **Location**: \`${uri}${line}\`\n`;

      if (res.properties?.cwe && res.properties.cwe.length > 0) {
        md += `- **CWE**: ${res.properties.cwe.join(', ')}\n`;
      }
      if (res.properties?.owasp && res.properties.owasp.length > 0) {
        md += `- **OWASP**: ${res.properties.owasp.join(', ')}\n`;
      }
      if (res.properties?.mitre && res.properties.mitre.length > 0) {
        md += `- **MITRE ATT&CK**: ${res.properties.mitre.join(', ')}\n`;
      }

      md += `\n**Description**:\n${res.message.markdown || res.message.text}\n\n`;

      if (loc?.region?.snippet?.text) {
        md += `**Code Snippet**:\n\`\`\`\n${loc.region.snippet.text}\n\`\`\`\n\n`;
      }

      // Attack graph visualization if available
      const attackGraph = (res.properties as any)?.attackGraph;
      if (attackGraph && attackGraph.nodes && attackGraph.nodes.length > 0) {
        md += `**Attack Vector & Blast Radius Graph**:\n\`\`\`mermaid\nflowchart LR\n`;
        for (const n of attackGraph.nodes) {
          md += `    ${n.id}["${n.label}"]\n`;
        }
        for (const e of attackGraph.edges || []) {
          md += `    ${e.from} -->|"${e.label || 'exploits'}"| ${e.to}\n`;
        }
        md += `\`\`\`\n\n`;
      }

      // Remediation markdown or text
      const remMd = (res.properties as any)?.remediationMarkdown;
      if (remMd) {
        md += `> [!TIP]\n> **Remediation Guide**:\n> ${remMd}\n\n`;
      } else if (res.properties?.remediation) {
        md += `> [!TIP]\n> **Remediation Advice**:\n> ${res.properties.remediation}\n\n`;
      }

      // Suggested code fixes
      if (res.fixes && res.fixes.length > 0) {
        md += `**Suggested Fix**:\n`;
        for (const fix of res.fixes) {
          md += `*${fix.description.text}*\n`;
          for (const ch of fix.changes || []) {
            for (const rep of ch.replacements) {
              md += `\`\`\`diff\n+// Replacement for ${ch.artifactLocation.uri} (Lines ${rep.deletedRegion.startLine}-${rep.deletedRegion.endLine}):\n${rep.insertedContent?.text || ''}\n\`\`\`\n`;
            }
          }
        }
        md += `\n`;
      }

      md += `---\n\n`;
    }

    return md;
  }

  /**
   * Saves Markdown report to file
   */
  public saveMarkdownToFile(outputPath: string): void {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, this.exportMarkdownSummary(), 'utf-8');
  }
}
