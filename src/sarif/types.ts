/**
 * TypeScript Type Definitions for OASIS SARIF v2.1.0 Specification
 * (Static Analysis Results Interchange Format)
 */

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: SarifToolDriver;
  };
  invocations?: SarifInvocation[];
  results: SarifResult[];
  taxonomies?: SarifTaxonomy[];
}

export interface SarifToolDriver {
  name: string;
  version: string;
  informationUri?: string;
  rules: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  defaultConfiguration?: {
    level: 'none' | 'note' | 'warning' | 'error';
  };
  help?: {
    text: string;
    markdown?: string;
  };
  helpUri?: string;
  properties?: {
    tags?: string[];
    cwe?: string[];
    owasp?: string[];
    mitre?: string[];
    cvssScore?: number;
    cvssVector?: string;
    precision?: 'very-high' | 'high' | 'medium' | 'low';
    problemSeverity?: 'error' | 'warning' | 'recommendation';
  };
}

export interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc?: string;
  startTimeUtc?: string;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: 'none' | 'note' | 'warning' | 'error';
  message: {
    text: string;
    markdown?: string;
  };
  locations?: SarifLocation[];
  fixes?: SarifFix[];
  properties?: {
    confidence?: 'high' | 'medium' | 'low';
    cvssScore?: number;
    cwe?: string[];
    owasp?: string[];
    mitre?: string[];
    exploitability?: string;
    remediation?: string;
  };
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
  logicalLocations?: Array<{
    name: string;
    kind?: string;
  }>;
}

export interface SarifFix {
  description: {
    text: string;
  };
  changes?: Array<{
    artifactLocation: {
      uri: string;
    };
    replacements: Array<{
      deletedRegion: {
        startLine: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
      insertedContent?: {
        text: string;
      };
    }>;
  }>;
}

export interface SarifTaxonomy {
  name: string;
  version?: string;
  organization?: string;
  shortDescription?: {
    text: string;
  };
  taxa: Array<{
    id: string;
    name: string;
    shortDescription?: {
      text: string;
    };
  }>;
}

export interface AuditFindingInput {
  ruleId: string;
  ruleName: string;
  level: 'error' | 'warning' | 'note';
  message: string;
  markdownMessage?: string;
  filePath?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
  endpointUri?: string;
  cvssScore?: number;
  cvssVector?: string;
  cwe?: string[];
  owasp?: string[];
  mitre?: string[];
  remediation?: string;
  tags?: string[];
}
