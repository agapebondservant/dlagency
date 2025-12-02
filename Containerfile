FROM tiangolo/uvicorn-gunicorn-fastapi:python3.11

COPY ./requirements.txt /app/requirements.txt

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install -r /app/requirements.txt

COPY ./api /app