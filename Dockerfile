FROM python:3.13-slim

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

RUN mkdir -p /app/plugins /app/background /app/icon
COPY default.png market.png /app/icon/

EXPOSE 12139

# 2 workers is enough for a registry; adjust with GUNICORN_WORKERS env if needed
ENV GUNICORN_WORKERS=2

CMD ["sh", "-c", "gunicorn app:app \
     --bind 0.0.0.0:12139 \
     --workers ${GUNICORN_WORKERS} \
     --timeout 60 \
     --access-logfile - \
     --error-logfile -"]
