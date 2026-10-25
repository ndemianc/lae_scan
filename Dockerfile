# eox-scan image. Syft and xeol are not installed here: mount pinned binaries and
# point EOX_SYFT_BIN / EOX_XEOL_BIN at them, or scan an existing SBOM.
FROM python:3.12-slim

WORKDIR /opt/eox_scan
COPY pyproject.toml README.md LICENSE tools.lock ./
COPY eox_scan ./eox_scan
COPY data ./data
COPY replay ./replay
RUN pip install --no-cache-dir . \
 && eox-scan snapshot build --src data/snapshot-2026-10-22 --out /opt/eox_scan/build/snapshot --as-of 2026-10-22

ENTRYPOINT ["eox-scan"]
CMD ["--help"]
