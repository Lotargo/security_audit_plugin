# Immutable Backup Standards & WORM Specifications

## AWS S3 Object Lock Modes

1. **Governance Mode**:
   - Protects objects from being deleted or overwritten by most users.
   - Users with specific IAM permissions (`s3:BypassGovernanceRetention`) can still delete objects.
   - **Risk:** Compromised root or admin credentials can purge all backups.

2. **Compliance Mode**:
   - Objects cannot be deleted or modified by ANY user, including the root account.
   - Retention period cannot be shortened.
   - **Recommended:** Mandatory for critical ransomware-resilient backup buckets.

## Air-Gapping & Multi-Party Authorization (MPA)
- Enforce decoupled IAM credentials for backup planes (different AWS organization / Azure tenant).
- Require MPA approval workflows for retention policy alterations.
