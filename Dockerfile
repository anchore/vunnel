# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY . vunnel
WORKDIR /vunnel

RUN pip install .
ENTRYPOINT ["vunnel"]
