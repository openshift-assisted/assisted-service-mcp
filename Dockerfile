FROM registry.redhat.io/ubi9/python-311:9.6

ENV APP_HOME=/opt/app-root/src
WORKDIR ${APP_HOME}

RUN pip install uv

COPY pyproject.toml .
COPY uv.lock .
RUN uv sync

COPY server.py .
COPY service_client ./service_client/

RUN chown -R 1001:0 ${APP_HOME}

USER 1001

EXPOSE 8000

CMD ["uv", "--cache-dir", "/tmp/uv-cache", "run", "server.py"]
