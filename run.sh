#!/bin/bash

docker rm -f maskmaker 2>/dev/null || true

docker build . -t cryptotest && docker run --name maskmaker cryptotest 
docker cp maskmaker:/client/mask.npy .
