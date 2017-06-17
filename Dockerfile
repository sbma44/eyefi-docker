FROM armv7/armhf-ubuntu_core:14.04

EXPOSE 59278

RUN bash -c "mkdir -p /tmp/eyefiserver && \
    apt-get update -y && \
    apt-get install -y python=2.7.5-5ubuntu3 python-setuptools && \
    easy_install flickr_api"

ADD eyefiserver.py .
ADD eyefiserver.conf .
ADD flickr.verifier .

ENTRYPOINT [ "python", "eyefiserver.py" ]
