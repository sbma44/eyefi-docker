FROM ubuntu:14.04

EXPOSE 59278

RUN mkdir -p /tmp/eyefiserver && \
    apt-get update -y && \
    apt-get install -y python=2.7.5-5ubuntu3 python-setuptools python-pip && \
    pip install flickr_api

ADD eyefiserver.py .
ADD eyefiserver.conf .
ADD flickr.verifier .

ENTRYPOINT [ "python", "eyefiserver.py" ]