# Example Mobile AppSec Finding: Plaintext Token in SharedPreferences

### Finding Details
- **Title:** Unencrypted JWT Authentication Token Stored in SharedPreferences
- **Severity:** High (CVSS 7.5)
- **Standard:** OWASP MASVS-STORAGE V1.1
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

### Vulnerable Source Code
```kotlin
// SessionManager.kt
val sharedPref = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
sharedPref.edit().putString("auth_token", jwtToken).apply()
```

### Hardened Implementation
Use `EncryptedSharedPreferences` backed by the Android Keystore:
```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_user_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

encryptedPrefs.edit().putString("auth_token", jwtToken).apply()
```
