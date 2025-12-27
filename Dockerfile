FROM registry.access.redhat.com/ubi9/python-311:9.7-1766406230

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

LABEL com.redhat.component="assisted-service-mcp" \
      name="assisted-service-mcp" \
      description="MCP server for OpenShift Assisted Installer Service" \
      io.k8s.description="MCP server for OpenShift Assisted Installer Service" \
      distribution-scope="public" \
      release="main" \
      version="latest" \
      url="https://github.com/openshift-assisted/assisted-service-mcp" \
      vendor="Red Hat, Inc."

CMD ["uv", "--cache-dir", "/tmp/uv-cache", "run", "python", "-m", "assisted_service_mcp.src.main"]
