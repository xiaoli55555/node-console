FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data COOKIE_SECURE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home panel && mkdir /data && chown panel:panel /data
COPY server.py network.py credential_store.py ip_dns.py dns_worker.py detectors.py rotation.py rotation_insights.py rotation_dns.py failover.py server_failover.py shared_failover.py hkt_dhcp.py ./
COPY web ./web
COPY agent ./agent
COPY probe ./probe
USER panel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)"
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "90", "server:app"]
