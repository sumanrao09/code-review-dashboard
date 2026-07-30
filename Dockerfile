# Secure Code Review Dashboard — app + all scanner CLIs in one image.
# semgrep (pip), scc + snyk (static binaries), sonar-scanner (bundled JRE).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    RUNNING_IN_DOCKER=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# ---- scanner CLIs ----------------------------------------------------------
ARG SCC_VERSION=3.7.0
ARG SONAR_SCANNER_VERSION=7.1.0.4889

RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  scc_arch=x86_64;  snyk_bin=snyk-linux;       ss_arch=linux-x64;     ;; \
      aarch64) scc_arch=arm64;   snyk_bin=snyk-linux-arm64; ss_arch=linux-aarch64; ;; \
      *) echo "unsupported arch: $arch"; exit 1 ;; \
    esac; \
    # scc — code metrics / profiler
    curl -fsSL -o /tmp/scc.tar.gz \
      "https://github.com/boyter/scc/releases/download/v${SCC_VERSION}/scc_Linux_${scc_arch}.tar.gz"; \
    tar -xzf /tmp/scc.tar.gz -C /usr/local/bin scc; \
    chmod +x /usr/local/bin/scc; rm /tmp/scc.tar.gz; \
    # snyk — static binary (reads SNYK_TOKEN env; no `snyk auth` needed)
    curl -fsSL -o /usr/local/bin/snyk "https://static.snyk.io/cli/latest/${snyk_bin}"; \
    chmod +x /usr/local/bin/snyk; \
    # sonar-scanner — ships its own JRE, so no Java install needed
    curl -fsSL -o /tmp/ss.zip \
      "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-${ss_arch}.zip"; \
    unzip -q /tmp/ss.zip -d /opt; rm /tmp/ss.zip; \
    ln -s /opt/sonar-scanner-*/bin/sonar-scanner /usr/local/bin/sonar-scanner

# ---- app -------------------------------------------------------------------
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt semgrep

COPY app ./app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
