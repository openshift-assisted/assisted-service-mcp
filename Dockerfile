FROM registry.access.redhat.com/ubi9/python-311:9.6

ENV APP_HOME=/opt/app-root/src
WORKDIR ${APP_HOME}

USER 0

RUN pip install uv

COPY pyproject.toml .
COPY uv.lock .
RUN uv sync

COPY server.py .
COPY service_client ./service_client/

RUN chown -R 1001:0 ${APP_HOME}

USER 1001

# Disable file logging in containers - only log to stderr
ENV LOG_TO_FILE=false

EXPOSE 8000

CMD ["uv", "--cache-dir", "/tmp/uv-cache", "run", "server.py"]
