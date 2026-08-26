FROM python:3.12-slim
WORKDIR /app
COPY gateway.py /app/gateway.py
USER 65534:65534
EXPOSE 8080
CMD ["python", "/app/gateway.py"]
