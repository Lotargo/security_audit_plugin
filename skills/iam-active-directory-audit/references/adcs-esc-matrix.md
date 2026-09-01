# AD CS ESC1-ESC8 Template Misconfigurations Reference

| Identifier | Key Condition | Threat Scenario |
| :--- | :--- | :--- |
| **ESC1** | Client Authentication EKU + `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Permissive Enrollment | Low-privilege user requests cert specifying Domain Admin SAN -> Full Domain Compromise |
| **ESC2** | Any Purpose EKU or No EKU + Permissive Enrollment | Certificate can be used for arbitrary EKU actions |
| **ESC3** | Certificate Request Agent EKU (Enrollment Agent) | Requestor can act as enrollment agent to issue certs on behalf of other users |
| **ESC4** | Insecure Template ACL (`WriteDacl`, `GenericAll` to low-privilege group) | Attacker modifies template parameters to convert into ESC1 |
| **ESC8** | AD CS HTTP Web Enrollment (`certsrv`) enabled without EPA/HTTPS | NTLM relay from coerced machine account (PetitPotam) to AD CS endpoint |
