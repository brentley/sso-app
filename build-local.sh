#!/bin/bash
set -e

echo "Creating build-info.json with current git information..."

COMMIT_HASH=$(git rev-parse HEAD)
SHORT_SHA=${COMMIT_HASH:0:7}
BRANCH=$(git branch --show-current)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > build-info.json << EOF
{
  "git_commit": "${COMMIT_HASH}",
  "git_commit_short": "${SHORT_SHA}",
  "build_date": "${BUILD_DATE}",
  "version": "${BRANCH}",
  "build_number": "local-$(date +%s)"
}
EOF

echo "Build info created:"
cat build-info.json

echo -e "\nBuilding Docker image for AMD64 platform..."
docker build --platform linux/amd64 -t ghcr.io/brentley/sso-app:latest .

echo -e "\nPushing to GHCR..."
docker push ghcr.io/brentley/sso-app:latest

echo -e "\nBuild and push complete!"
echo "Commit: ${SHORT_SHA}"
echo "Build date: ${BUILD_DATE}"