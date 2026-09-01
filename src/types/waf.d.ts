declare module '*/sandbox_runtime/stealth/waf_detector.js' {
  export interface WafDetectionHit {
    profile_id: string;
    name: string;
    confidence: number;
    signals: string[];
    capabilities_needed: string[];
    strategy: {
      tls_impersonate?: string[];
      referer?: string;
      warmup_required?: boolean;
      recommendation?: string;
    };
  }

  export interface WafDetectInput {
    headers?: Record<string, string>;
    cookies?: Array<{ name: string; value: string }> | string[];
    body?: string;
    status?: number;
  }

  export class WafDetector {
    static detect(response: WafDetectInput): WafDetectionHit[];
  }
}
