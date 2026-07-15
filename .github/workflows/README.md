# workflows

GitHub Actions pipelines for fiducia-edge:

- `ci.yml` — install, lint, and test the Worker on push and pull request. The
  sibling `fiducia-interfaces` checkout is pinned to its exact full commit SHA
  so the `file:../` dependency cannot drift between runs.

This repository does not receive Cloudflare deployment credentials. In
particular, CI never invokes Wrangler against its default environment; release
orchestration belongs to `fiducia-monorepo`.

## Security baseline

Every executable workflow uses explicit least-privilege permissions, immutable
third-party action or container references, non-persisted checkout credentials,
concurrency control, and a job timeout. The main CI workflow validates this
directory with the digest-pinned actionlint container. Environment mutation is
forbidden unless this README documents a repository-specific platform exception.
