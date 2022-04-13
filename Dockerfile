## Image with CUDA support
FROM nvidia/cuda:10.2-devel
RUN apt-get update && apt-get install -y python3-dev curl git

RUN cd /tmp && curl -O https://bootstrap.pypa.io/get-pip.py \
    && python3 get-pip.py

WORKDIR /client

COPY ./requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt
COPY config.toml config.toml
COPY test.py test.py

ENTRYPOINT ["python3"]
CMD ["test.py"]

