# Cerberus: three scanners + the orchestrator CLI in one image.
# Scanner versions are pinned — bump deliberately, one at a time.

FROM node:24-slim AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --no-fund --no-audit
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-slim
ARG TARGETARCH
ARG SEMGREP_VERSION=1.169.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.72.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends git curl ca-certificates python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages semgrep==${SEMGREP_VERSION}

# The two Go scanners name their release assets differently per architecture.
RUN set -eux; \
  case "${TARGETARCH}" in \
    amd64) gl_arch=x64;   tv_arch=64bit ;; \
    arm64) gl_arch=arm64; tv_arch=ARM64 ;; \
    *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
  curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy

WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
RUN ln -s /app/dist/index.js /usr/local/bin/cerberus && chmod +x /app/dist/index.js

# The scan target is a bind-mounted or CI-checked-out tree owned by another
# uid; without this git refuses to run and changed-file detection goes silently
# empty.
RUN git config --global --add safe.directory '*'

# Scan target is mounted (or checked out by CI) at /src.
WORKDIR /src
ENTRYPOINT ["cerberus"]
CMD ["scan"]
