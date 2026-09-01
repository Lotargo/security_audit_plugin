# Subdomain Takeover Signatures Reference

| Cloud Service Provider | Canonical CNAME Pattern | Fingerprint Error Response |
| :--- | :--- | :--- |
| **GitHub Pages** | `<username>.github.io` | `There isn't a GitHub Pages site here.` |
| **AWS S3 Bucket** | `<bucket>.s3.amazonaws.com` | `The specified bucket does not exist` (NoSuchBucket) |
| **Heroku** | `<app>.herokuapp.com` | `No such app` / `herokucdn.com/error-pages/no-such-app.html` |
| **Azure App Service** | `<app>.azurewebsites.net` | `404 Web Site not found.` |
| **Surge.sh** | `na-west1.surge.sh` | `project not found` |
