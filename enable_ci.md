# Re-enable GitHub Actions

When ready to re-enable automatic builds, make this change to `.github/workflows/build-and-deploy.yml`:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:  # Allow manual triggers
```

Then commit and push:
```bash
git add .github/workflows/build-and-deploy.yml
git commit -m "re-enable automatic GitHub Actions builds"
git push
```