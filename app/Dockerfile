FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY templates ./templates
COPY static ./static

# Run as non-root; /data holds the SQLite db (mounted volume).
RUN useradd -u 1000 -m app && mkdir /data && chown app:app /data
USER app

ENV DB_PATH=/data/perch.db
EXPOSE 8000

# slim has no curl; probe /healthz with the stdlib instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
