# Android Manifest Security Flags Reference

| Attribute | Insecure Setting | Recommended Setting | Security Risk |
| :--- | :--- | :--- | :--- |
| `android:exported` | `true` (without `android:permission`) | `false` (explicit) | Component accessible to any third-party app on device |
| `android:debuggable` | `true` | `false` | Memory attachment, debugger access, heap inspection |
| `android:allowBackup` | `true` (without filter) | `false` | App data extracted via `adb backup` |
| `android:usesCleartextTraffic` | `true` | `false` | Unencrypted HTTP traffic allowed |
| `PendingIntent` flags | `FLAG_MUTABLE` | `FLAG_IMMUTABLE` | Intent parameter injection / hijacking |
