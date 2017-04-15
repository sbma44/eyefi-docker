FROM ubuntu:14.04

PORT 59278

RUN apt-get update -y && \


ADD eyefiserver.py .

ENTRYPOINT [ "python3", "eyefiserver.py" ]