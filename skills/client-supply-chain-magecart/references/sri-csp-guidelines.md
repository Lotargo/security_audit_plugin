# Subresource Integrity (SRI) & CSP Directives

## Subresource Integrity Example
```html
<!-- Correct SRI Binding -->
<script 
  src="https://cdn.example.com/libs/framework@2.4.1.min.js" 
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" 
  crossorigin="anonymous">
</script>
```

## CSP Directives for Payment Pages
```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-rAnd0mN0nc3' https://js.stripe.com;
  connect-src 'self' https://api.stripe.com;
  frame-src https://js.stripe.com;
  form-action 'self' https://api.stripe.com;
  base-uri 'none';
  report-to /api/csp-violation-reports;
```
