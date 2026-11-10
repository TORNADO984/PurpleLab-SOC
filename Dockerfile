FROM python:3.13.7-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY purplelab /app/purplelab
COPY rules /app/rules
COPY scenarios /app/scenarios
COPY configs /app/configs
COPY dashboards /app/dashboards
COPY scripts /app/scripts
USER 1000:0
ENTRYPOINT ["python", "-m", "purplelab"]
