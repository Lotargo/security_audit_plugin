# Injection Vulnerabilities & CWE Mappings

| Vulnerability Type | Common Sinks | CWE ID | OWASP Category |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | `db.query()`, `cursor.execute(f"...")`, raw ORM methods | CWE-89 | A03:2021-Injection |
| **OS Command Injection** | `child_process.exec()`, `os.system()`, `subprocess.Popen(shell=True)` | CWE-78 | A03:2021-Injection |
| **Server-Side Template Injection** | `jinja2.Template()`, `Environment.from_string()` | CWE-1336 | A03:2021-Injection |
| **XML External Entity (XXE)** | `DocumentBuilderFactory`, `SAXParserFactory` (DTD enabled) | CWE-611 | A05:2021-Security Misconfiguration |
| **Server-Side Request Forgery** | `fetch(url)`, `http.get(url)`, `urllib.request.urlopen()` | CWE-918 | A10:2021-SSRF |
| **Insecure Deserialization** | `pickle.loads()`, `ObjectInputStream.readObject()`, `unserialize()` | CWE-502 | A08:2021-Software & Data Integrity |
| **NoSQL Injection** | `db.collection.find({ username: req.body.user })` ($ne operator) | CWE-943 | A03:2021-Injection |
