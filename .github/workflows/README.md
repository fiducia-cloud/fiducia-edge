# workflows

GitHub Actions pipelines for fiducia-edge:

- `ci.yml` — install, lint, and test the Worker on push and pull request. The
  sibling `fiducia-interfaces` checkout is pinned to its exact full commit SHA
  so the `file:../` dependency cannot drift between runs.
- `deploy-test.yml` — secret-gated deploy of the Worker to the TEST environment;
  missing credentials fail the deployment rather than producing a green no-op,
  using the same immutable interfaces checkout as CI.
