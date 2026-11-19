#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_EVENT_NAME:-}" != "push" || "${GITHUB_REF:-}" != "refs/heads/main" ]]; then
    exit 0
fi

[[ "${CLIENT_ID:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: CLIENT_ID"; exit 1; }
[[ "${KID:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: KID"; exit 1; }
[[ "${PRIVATE_KEY:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: PRIVATE_KEY"; exit 1; }
[[ "${TOKEN_ENDPOINT:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: TOKEN_ENDPOINT"; exit 1; }
[[ "${ISSUER:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: ISSUER"; exit 1; }
[[ "${API_BASE_URL:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: API_BASE_URL"; exit 1; }
[[ "${READ_SCOPES:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: READ_SCOPES"; exit 1; }
[[ "${WRITE_SCOPES:-}" =~ [^[:space:]] ]] || { echo "::error::Missing sandbox credential: WRITE_SCOPES"; exit 1; }
