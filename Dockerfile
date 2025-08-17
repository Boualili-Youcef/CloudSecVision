FROM python:3.11-slim

LABEL maintainer="Youcef BOUALILI <youcefboualili0@gmail.com>"
LABEL description="CloudSecVision - AWS Security Scanner with AI Analysis"
LABEL version="1.0"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8501

RUN useradd --create-home --shell /bin/bash cloudsec
WORKDIR /home/cloudsec/app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=cloudsec:cloudsec . .

RUN mkdir -p scan/results && \
    chown -R cloudsec:cloudsec scan/results

USER cloudsec

EXPOSE $PORT

ENTRYPOINT ["streamlit", "run", "dashboard.py"]
CMD ["--server.port", "8501", "--server.address", "0.0.0.0", "--server.headless", "true"]