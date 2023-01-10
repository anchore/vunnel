# syntax=docker/dockerfile:1
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt update && apt install -y git && rm -rf /var/lib/apt/lists/*

COPY dist dist
RUN pip install ./dist/vunnel-*.whl
ENTRYPOINT ["vunnel"]

LABEL org.opencontainers.image.source https://github.com/anchore/vunnel
LABEL org.opencontainers.image.description "A tool for pulling and processing vulnerability data from mutiple sources"
