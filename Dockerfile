# Cerberus: three scanners + the orchestrator CLI in one image.
# Scanner versions are pinned — bump deliberately, one at a time.

FROM node:24-slim AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --no-fund --no-audit
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-slim
ARG SEMGREP_VERSION=1.96.0
ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.58.1

RUN apt-get update \
  && apt-get install -y --no-install-recommends git curl ca-certificates python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages semgrep==${SEMGREP_VERSION}

RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
  && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy

WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
RUN ln -s /app/dist/index.js /usr/local/bin/cerberus && chmod +x /app/dist/index.js

# Scan target is mounted (or checked out by CI) at /src.
WORKDIR /src
ENTRYPOINT ["cerberus"]
CMD ["scan"]
