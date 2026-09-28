FROM python:3.12.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app
WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin aegis
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]

FROM runtime AS test
USER root
COPY requirements-dev.lock ./requirements-dev.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY pyproject.toml ./pyproject.toml
COPY tests ./tests
USER 10001:10001
CMD ["pytest", "-m", "integration", "-p", "no:cacheprovider"]
