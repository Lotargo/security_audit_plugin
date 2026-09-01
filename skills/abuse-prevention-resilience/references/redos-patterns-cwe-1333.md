# ReDoS Catastrophic Backtracking Patterns (CWE-1333)

## Classic Vulnerable Patterns

1. **Nested Quantifiers with Repetition:**
   - Pattern: `(a+)+$`
   - Vulnerable Input: `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!`
   - Complexity: $O(2^N)$ exponential steps.

2. **Overlapping Alternations:**
   - Pattern: `(a|a)+$` or `(a|ab)+$`
   - Vulnerable Input: `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!`

3. **Wildcards with Overlapping Suffixes:**
   - Pattern: `^([a-zA-Z0-9_]+)*@example\.com$`
   - Vulnerable Input: `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!`

## Remediation Strategies
- Use non-backtracking linear engines: Google RE2, Rust `regex` crate.
- Apply strict evaluation timeouts (e.g., abort regex match after 25ms).
- Avoid nested variable-length quantifiers (`*`, `+`).
