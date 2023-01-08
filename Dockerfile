# syntax=docker/dockerfile:1
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt update && apt install -y git && rm -rf /var/lib/apt/lists/*

COPY . src
RUN pip install ./src
ENTRYPOINT ["vunnel"]

# TODO: change to vunnel repo later
LABEL org.opencontainers.image.source https://github.com/anchore/grype-db-builder
