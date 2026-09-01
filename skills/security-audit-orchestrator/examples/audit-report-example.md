# Security Audit Report: ACME Staging Environment

**Audit ID:** `audit-20260901-acme`  
**Date:** 2026-09-01  
**Mode:** Hybrid (Source Code + Live DAST)  
**Status:** Completed  

---

## Executive Summary

A comprehensive security audit of `https://staging.acme.com` was conducted across multiple domains including AST code analysis, live API probing, and infrastructure configuration review.

### Risk Overview

| Critical | High | Medium | Low | Total |
| :---: | :---: | :---: | :---: | :---: |
| 1 | 2 | 3 | 0 | 6 |

---

## Findings Details

### [SEC-01] SQL Injection in Product Search API
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Component:** `src/controllers/searchController.ts:42` / `/api/v1/search?q=`
- **Description:** User input passed via query parameter `q` is directly concatenated into SQL query without parameterized binding.
- **Remediation:** Utilize parameterized queries / Prisma ORM prepared statements.

---

## Machine-Readable SARIF
The standardized SARIF v2.1.0 output is available at `/workspace/reports/audit-report.sarif`.
