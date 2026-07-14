FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENV HOST=0.0.0.0
ENV PORT=8787

EXPOSE 8787

CMD ["python", "monitor_server.py"]
