FROM python:3.13-slim

# System dependencies: WeasyPrint (PDF rendering) + Nuclei (Go binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (pinned release, avoids "latest" surprises breaking builds)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY scanner/ ./scanner/
COPY reports/ ./reports/

# Pre-fetch Nuclei templates at build time so first scan isn't slow
RUN nuclei -update-templates -silent || true

EXPOSE 8001

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8001"]