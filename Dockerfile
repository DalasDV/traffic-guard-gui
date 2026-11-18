FROM python:3.13-slim-trixie
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd --gid 10001 panel \
 && useradd --uid 10001 --gid panel --no-create-home --shell /usr/sbin/nologin panel \
 && install -d -o panel -g panel -m 0700 /data /keys \
 && touch /data/.panel-volume /keys/.panel-volume \
 && chown panel:panel /data/.panel-volume /keys/.panel-volume
COPY app.py storage.py collector.py traffic-guard-reader ./
COPY static/ ./static/
USER 10001:10001
EXPOSE 4090
ENTRYPOINT ["python", "/app/app.py"]
CMD ["serve"]
