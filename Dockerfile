FROM registry.access.redhat.com/ubi9/python-311:9.7-1763483758

ENV APP_HOME=/opt/app-root/src
WORKDIR ${APP_HOME}

USER 0

RUN pip install uv

COPY pyproject.toml .
COPY uv.lock .
RUN uv sync

COPY assisted_service_mcp ./assisted_service_mcp/

RUN chown -R 1001:0 ${APP_HOME}

USER 1001

# Disable file logging in containers - only log to stderr
ENV LOG_TO_FILE=false

EXPOSE 8000

CMD ["uv", "--cache-dir", "/tmp/uv-cache", "run", "python", "-m", "assisted_service_mcp.src.main"]
