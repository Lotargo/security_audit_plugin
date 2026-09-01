# Cloud Instance Metadata Service (IMDS) Hardening

## IMDSv1 vs IMDSv2 (AWS EC2)

- **IMDSv1 Vulnerability:** Plain `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` without token headers. Any basic SSRF vulnerability can extract full instance IAM credentials.
- **IMDSv2 Defense:** Requires `PUT` request with token TTL header to fetch session token, then `GET` with token. Blocks standard GET-based SSRF and reverse proxy traversals.

```terraform
# Terraform AWS EC2 IMDSv2 Hardened Configuration
resource "aws_instance" "hardened_instance" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforces IMDSv2
    http_put_response_hop_limit = 1          # Prevents container/pod traversal
  }
}
```
