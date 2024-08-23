#!/bin/bash

docker-compose up -d

# Wait for the container to start
until docker inspect -f '{{.State.Status}}' app-acre-nanosp-1 | grep -q "running"; do
    sleep 1
done

docker exec -it app-acre-nanosp-1 ./tools/debug.sh apps/app.elf

docker-compose down