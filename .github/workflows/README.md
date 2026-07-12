# workflows

GitHub Actions pipelines for fiducia-edge:

- `ci.yml` — install, lint, and test the Worker on push and pull request.
- `deploy-test.yml` — secret-gated deploy of the Worker to the TEST environment;
  a no-op when the required deploy secret is absent (validation only).
