#!/bin/bash

echo "Tagging and pushing: $CIRCLE_TAG"
docker info
docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS
docker build -t quantum/dex:$CIRCLE_TAG .
docker push quantum/dex:$CIRCLE_TAG
