#!/bin/bash

# build app1 JAR files
app1/mvnw -f app1/pom.xml clean package

# build docker containers
docker-compose up -d --force-recreate --build
