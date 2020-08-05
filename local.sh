#!/bin/bash
export DJANGO_LOGLEVEL=DEBUG \
TA_SERVER=http://127.0.0.1:8000 \
ALLOWED_HOSTS=* \
DJANGO_DEBUG=True_or_False \
MINIO_ACCESS_KEY=minio_access_key_here \
MINIO_SECRET_KEY=minio_secret_key_here \
MINIO_BUCKET_NAME=bucket_name_here \
MINIO_URL=url_of_minio_here \
MINIO_SSL_SECURE=True_or_False \
MINIO_EXPIRE_GET=1 \
MINIO_EXPIRE_PUT=1
