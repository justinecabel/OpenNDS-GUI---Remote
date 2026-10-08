FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir flask gunicorn
COPY app.py .
COPY templates templates
COPY static static
COPY portal /portal-default
COPY portal-custom /portal-custom
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "90", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "app:app"]
