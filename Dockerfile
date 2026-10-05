FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY logpoint_mcp ./logpoint_mcp
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MITRE_CACHE_PATH=/var/cache/logpoint-mcp/enterprise-attack.json
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --home-dir /nonexistent mcp \
    && mkdir -p /var/cache/logpoint-mcp && chown mcp /var/cache/logpoint-mcp
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"
ENTRYPOINT ["logpoint-mcp"]
CMD ["--transport", "http"]
