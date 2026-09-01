# SLSA (Supply-chain Levels for Software Artifacts) Matrix

| SLSA Level | Core Requirement | Key Controls |
| :--- | :--- | :--- |
| **SLSA 1** | Build process is documented | Automated build script, provenance generated |
| **SLSA 2** | Tamper resistance of build service | Hosted build platform (GitHub Actions), signed provenance |
| **SLSA 3** | Hardened build platform | Isolated ephemeral build runners, non-falsifiable provenance |
| **SLSA 4** | Highest hermetic integrity | Two-party review, hermetic and reproducible builds |
