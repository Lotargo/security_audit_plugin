# AST Extraction Patterns & Heuristics

## Target AST Nodes in Bundles

1. **Axios Client Definitions**:
   - `CallExpression` where `callee.object.name === 'axios'` or `callee.name === 'create'`.
   - Property `baseURL` -> extract string literal or template literal.

2. **Route Strings & URL Templates**:
   - `Literal` / `StringLiteral` matching regex `^(\/api\/|\/v[0-9]+\/|\/graphql|\/rpc)`.
   - `TemplateLiteral` with dynamic path variables (e.g. `/api/v1/users/${id}`).

3. **Validation Schema Definitions**:
   - Zod: `z.object({ ... })`
   - Yup: `yup.object().shape({ ... })`
   - Joi: `Joi.object({ ... })`

4. **gRPC-Web & Connect Stubs**:
   - Method declarations with `MethodDescriptor`, `requestType`, `responseType`.
   - Protobuf message definitions with field tags and wire types.
