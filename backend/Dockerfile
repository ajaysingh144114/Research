# QSign API as a container (Amazon ECS/Fargate, EKS or on-premises).
# Uses the same environment variables as the Lambda deployment.
FROM python:3.13-slim

RUN useradd --create-home --uid 10001 qsign
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "uvicorn[standard]>=0.30"
COPY qsign ./qsign

USER qsign
ENV QSIGN_MODE=kms
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "qsign.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
