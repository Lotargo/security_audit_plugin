# RFC 9112 & RFC 9113 Protocol Desynchronization Reference

## Smuggling Taxonomy

| Variant | Frontend Behavior | Backend Behavior | Resulting Vulnerability |
| :--- | :--- | :--- | :--- |
| **CL.TE** | Reads `Content-Length` | Reads `Transfer-Encoding: chunked` | Remaining payload treated as start of next request |
| **TE.CL** | Reads `Transfer-Encoding: chunked` | Reads `Content-Length` | Backend socket hangs waiting for bytes; subsequent request appended |
| **TE.TE** | Obfuscated TE header processed | Obfuscated TE header ignored | Fallback to CL on backend, triggering CL.TE or TE.CL |
| **H2.CL** | Translates H2 to H1 with injected CL | Processes injected CL | Backend interprets translated request boundary incorrectly |
| **H2.TE** | Translates H2 to H1 with injected TE | Processes chunked stream | Desynchronizes HTTP/1.1 backend connection |

## RFC 9112 Section 6.3 Rule
If a message is received with both `Transfer-Encoding` and `Content-Length` header fields, `Transfer-Encoding` MUST override `Content-Length`, or the server MUST reject the message with a 400 (Bad Request) status code.
