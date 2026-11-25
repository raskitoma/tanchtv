FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# ffmpeg: remuxes the stream to MPEG-TS *with PCR* for VLC links (go2rtc's own TS has no PCR, which makes
# VLC drift further and further behind live).
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY *.py ./
COPY static ./static
VOLUME ["/data"]
EXPOSE 8095
CMD ["python", "server.py"]
