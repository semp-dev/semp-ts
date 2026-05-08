# semp

TypeScript implementation of [SEMP](https://github.com/semp-dev/semp-spec)
(Sealed Envelope Messaging Protocol). Compiles to plain JavaScript with
TypeScript declaration files; the published npm package serves both
JavaScript and TypeScript callers from the same artifact.

Targets Node.js (>=20) and modern browsers. The crypto stack is the
audited [@noble](https://github.com/paulmillr/noble) suite end to end:
no native bindings, pure-JS, browser-compatible.

## Status

Pre-1.0 development. Implementation tracks the [`semp-spec`](https://github.com/semp-dev/semp-spec)
test vectors at `vectors/v1.0.0/`. Conformance is gated on the cross-language
vectors-runner under `test/vectors/`; a build is interop-ready when the
runner reports all vectors green.

| Layer | Coverage |
|-------|----------|
| 1 (cryptographic primitives)   | scaffolding |
| 2 (deterministic protocol)     | TODO        |
| 3 (envelope round-trip)        | TODO        |
| 4 (handshake messages)         | TODO        |
| 5 (signed documents)           | TODO        |

## Repository layout

Each `src/<layer>/` mirrors the corresponding semp-go package so anyone
fluent in one can read the other.

```
src/
  crypto/   (Layer 1 primitives: HKDF, HMAC, AEAD, KEM, signatures)
  ...       (more as layers land)
test/
  vectors/  (JSON-driven cross-language vectors runner)
```

## Development

```sh
npm install
npm test              # run vitest once
npm run test:watch    # watch mode
npm run typecheck     # strict tsc, no emit
npm run build         # emit .js + .d.ts to dist/
```

The vectors runner expects `semp-spec/vectors/v1.0.0/` as a sibling
checkout, or `SEMP_VECTORS_DIR` set explicitly:

```sh
SEMP_VECTORS_DIR=/path/to/semp-spec/vectors/v1.0.0 npm test
```

## License

MIT. See [LICENSE](./LICENSE).
