# PCI DSS v4.0 Client-Side Requirements Overview

## Requirement 6.4.3 (Script Governance & Integrity)
- **Mandate:** All scripts loaded and executed in the consumer's browser on payment pages must be managed and authorized.
- **Controls:**
  1. Method to confirm that each script is authorized with documented business justification.
  2. Method to ensure the integrity of each script (e.g. Subresource Integrity `integrity="sha384-..."`).
  3. Maintained script inventory with description and ownership.

## Requirement 11.6.1 (Tamper Detection on Payment Pages)
- **Mandate:** A change-and-tamper-detection mechanism must be deployed to alert personnel to unauthorized modifications (including script injection or header tampering) to payment pages.
- **Controls:**
  1. Evaluated at least once every seven days or periodically per risk assessment.
  2. Synthesized CSP violation reports, DOM hash monitoring, or third-party client-side WAFs.
