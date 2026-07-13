# workflows

GitHub Actions pipelines for fiducia-edge:

- `ci.yml` — install, lint, and test the Worker on push and pull request. The
  sibling `fiducia-interfaces` checkout is pinned to its exact full commit SHA
  so the `file:../` dependency cannot drift between runs.
- `deploy-test.yml` — secret-gated deploy of the Worker to the TEST environment;
  a no-op when the required deploy secret is absent (validation only), using
  the same immutable interfaces checkout as CI.
