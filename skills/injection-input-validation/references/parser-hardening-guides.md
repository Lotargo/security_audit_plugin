# Parser Hardening & Secure Parsing Guides

## 1. Secure XML Parsing (Java XXE Defense)
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

## 2. Secure Outbound Request Handler (SSRF Defense)
```typescript
import ipaddr from 'ipaddr.js';

function isAllowedUrl(inputUrl: string): boolean {
  const parsed = new URL(inputUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  
  // Resolve IP and check against private / link-local subnets
  const ip = ipaddr.parse(parsed.hostname);
  const range = ip.range();
  if (['private', 'loopback', 'linkLocal', 'uniqueLocal'].includes(range)) {
    return false; // Block RFC 1918 & Cloud metadata 169.254.169.254
  }
  return true;
}
```
