#!/bin/bash
export DJANGO_LOGLEVEL=DEBUG \
TA_SERVER=http://127.0.0.1:8000/api/v1/search/ \
ALLOWED_HOSTS=* \
DJANGO_DEBUG=True