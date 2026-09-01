# DOM XSS Sinks & Sources Catalogue

## Insecure Sources
- `location.search`, `location.hash`, `location.pathname`, `location.href`
- `document.URL`, `document.documentURI`, `document.referrer`
- `window.name`
- `postMessage` data payload (`event.data`)
- `sessionStorage` / `localStorage` items previously influenced by third-party scripts

## Execution Sinks
- **HTML Injection Sinks:** `element.innerHTML`, `element.outerHTML`, `document.write()`, `document.writeln()`
- **JavaScript Execution Sinks:** `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- **DOM Navigation Sinks:** `location.href = ...`, `location.assign(...)`, `location.replace(...)`, `window.open(...)`
- **Script Insertion:** `document.createElement('script')` with `.src` derived from user input.
