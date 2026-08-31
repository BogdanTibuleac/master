# syntax=docker/dockerfile:1.7
# The platform image and every Python dependency are immutable version pins.
FROM python:3.12.11-slim-bookworm@sha256:c5247bc3787c809810386c289942bdf3b6e9437dc7436e1acfe7c822f446e3b5

LABEL org.opencontainers.image.title="malware-robustness disposable PE extractor" \
      org.opencontainers.image.description="Static-only, framed PE feature extraction; contains no model or credentials" \
      io.malware-robustness.runtime="network=none,read-only,cap-drop=ALL,no-new-privileges,non-root" \
      io.malware-robustness.seccomp="docker/extractor/seccomp-profile.json"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PYTHONSAFEPATH=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    HOME=/nonexistent

# Only dependencies required by the existing PE extractor are installed. The
# scoring model, cloud SDKs, shells as entrypoints, and credential helpers are
# deliberately absent.
RUN python -m pip install --no-cache-dir --disable-pip-version-check --only-binary=:all: \
      numpy==2.5.2 \
      pefile==2024.8.26 \
      scikit-learn==1.9.0 \
      scipy==1.18.1 \
      joblib==1.6.0 \
      threadpoolctl==3.6.0

WORKDIR /opt/extractor

COPY --chown=0:0 src/malware_robustness/__init__.py /usr/local/lib/python3.12/site-packages/malware_robustness/__init__.py
COPY --chown=0:0 src/malware_robustness/ember2018.py /usr/local/lib/python3.12/site-packages/malware_robustness/ember2018.py
COPY --chown=0:0 src/malware_robustness/pe_features.py /usr/local/lib/python3.12/site-packages/malware_robustness/pe_features.py
COPY --chown=0:0 src/malware_robustness/domain/__init__.py /usr/local/lib/python3.12/site-packages/malware_robustness/domain/__init__.py
COPY --chown=0:0 src/malware_robustness/domain/analysis.py /usr/local/lib/python3.12/site-packages/malware_robustness/domain/analysis.py
COPY --chown=0:0 src/malware_robustness/domain/extraction.py /usr/local/lib/python3.12/site-packages/malware_robustness/domain/extraction.py
COPY --chown=0:0 src/malware_robustness/domain/scans.py /usr/local/lib/python3.12/site-packages/malware_robustness/domain/scans.py
COPY --chown=0:0 src/malware_robustness/services/__init__.py /usr/local/lib/python3.12/site-packages/malware_robustness/services/__init__.py
COPY --chown=0:0 src/malware_robustness/services/extraction_runtime.py /usr/local/lib/python3.12/site-packages/malware_robustness/services/extraction_runtime.py

# UID/GID 65534 is also enforced by ContainerExtractorRunner. The image has no
# writable application directory and is intended to run with --read-only.
USER 65534:65534

STOPSIGNAL SIGKILL
ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "malware_robustness.services.extraction_runtime", "--extractor-child"]
