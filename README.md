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
test vectors at `vectors/v1.0.0/`. Conformance is gated on the
cross-language vectors-runner under `test/vectors/`; the runner
reports all vectors green at the currently published tag.

Suite coverage: baseline `x25519-chacha20-poly1305` and the
post-quantum hybrid `pq-kyber768-x25519`.


## Repository layout

Each `src/<package>/` mirrors the corresponding semp-go package so
anyone fluent in one can read the other.

```
src/
  crypto/           HKDF, HMAC, AEAD, KEM (X25519 + Kyber768 hybrid),
                    Ed25519 signatures
  canonical/        canonical JSON marshaler (ENVELOPE.md §4.3)
  keys/             Ed25519 sign/verify + SEMP fingerprint format
  brief/            brief construction and verification
  enclosure/        enclosure + forwarding chain
  envelope/         envelope canonical encoding, bucket math, compose
  seal/             per-recipient key wrap + unwrap
  handshake/        federation + client-to-server state machines,
                    PoW, confirmation hash, first-contact tokens
  session/          session keys, dispatcher, resumption tickets
  discovery/        well-known + DNS TXT discovery
  delivery/         delivery state, sync, conflict resolution
  largeattachment/  HKDF-Expand + ChaCha20/XChaCha20-Poly1305 chunks
  extensions/       layered extension registry + validation
  transparency/     STH, inclusion + consistency proofs
  recovery/         Argon2id + XChaCha20 recovery bundles, Shamir
  migration/        cooperative-migration signature chains
  reputation/       reputation references + observations
  closure/          account-closure documents
  clockskew/        clock-tolerance tiers
  transport/        h2 and WebSocket transports
test/
  vectors/          JSON-driven cross-language vectors runner
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
