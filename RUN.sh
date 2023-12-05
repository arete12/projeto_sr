#!/bin/bash


# keystore loc, var used on github action
export KEYSTORE_ALIAS=mykey
export KEYSTORE_PASSWORD=123456
export RUNNER_TEMP=`pwd`

# build app1 JAR files
app1/mvnw -X -f app1/pom.xml clean package

# build docker containers
docker-compose up --force-recreate --build
