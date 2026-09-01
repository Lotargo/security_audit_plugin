# Cloud IAM Privilege Escalation Paths Reference

## AWS IAM Dangerous Combinations

1. **`iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`**:
   - Attacker passes high-privilege IAM role to new Lambda function and invokes it to perform actions as that role.

2. **`iam:CreateAccessKey`**:
   - Directly creates access keys on another user account with higher privileges.

3. **`iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`**:
   - Modifies existing managed policy to add `*` on `*` administrator rights.

4. **`iam:AttachUserPolicy` / `iam:AttachRolePolicy`**:
   - Attaches `AdministratorAccess` policy to own identity.
