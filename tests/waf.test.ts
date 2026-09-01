import { describe, it, expect } from 'vitest';
import { WafDetector } from '../sandbox_runtime/stealth/waf_detector.js';

describe('WafDetector Multi-Signal Engine', () => {
  it('detects Akamai Bot Manager with high confidence on cookie & header signals', () => {
    const hits = WafDetector.detect({
      headers: {
        'x-akamai-transformed': '9 - 0 pmb=mRUM,1',
        server: 'AkamaiGHost',
      },
      cookies: ['_abck=1234567890', 'bm_sz=abcdef'],
      body: '<html><head><title>Access Control</title></head><body><h1>Welcome</h1></body></html>',
    });

    expect(hits.length).toBeGreaterThan(0);
    const akamai = hits.find((h: any) => h.profile_id === 'akamai_bot_manager');
    expect(akamai).toBeDefined();
    expect(akamai?.confidence).toBe(0.9);
    expect(akamai?.signals).toContain('cookie:_abck');
    expect(akamai?.signals).toContain('cookie:bm_sz');
    expect(akamai?.signals).toContain('header:x-akamai-*');
    expect(akamai?.signals).toContain('server:akamaighost');
    expect(akamai?.strategy.warmup_required).toBe(true);
  });

  it('detects Cloudflare Turnstile with challenge body phrase', () => {
    const hits = WafDetector.detect({
      headers: {
        'cf-ray': '8f1234567890-SJC',
        server: 'cloudflare',
      },
      cookies: ['__cf_bm=token123'],
      body: '<html><body>Just a moment... Enable JavaScript and cookies to continue</body></html>',
    });

    const cf = hits.find((h: any) => h.profile_id === 'cloudflare_turnstile');
    expect(cf).toBeDefined();
    expect(cf?.confidence).toBe(0.9);
    expect(cf?.signals).toContain('body:just a moment...');
    expect(cf?.signals).toContain('header:cf-ray');
  });

  it('detects AWS WAF on token cookie and amazon headers', () => {
    const hits = WafDetector.detect({
      headers: {
        'x-amzn-requestid': 'req-12345',
        'x-amz-cf-id': 'cf-999',
      },
      cookies: ['aws-waf-token=abcde'],
      body: 'Request blocked by AWS WAF',
    });

    const aws = hits.find((h: any) => h.profile_id === 'aws_waf');
    expect(aws).toBeDefined();
    expect(aws?.confidence).toBe(0.9);
    expect(aws?.signals).toContain('cookie:aws-waf-token');
    expect(aws?.signals).toContain('body:aws waf');
  });

  it('falls back to unknown_challenge on 403 status without specific vendor signatures', () => {
    const hits = WafDetector.detect({
      headers: {
        server: 'nginx',
      },
      cookies: [],
      body: '403 Forbidden',
      status: 403,
    });

    expect(hits.length).toBe(1);
    expect(hits[0].profile_id).toBe('unknown_challenge');
  });
});
