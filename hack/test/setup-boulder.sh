#!/bin/bash

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

BOULDER_REPO="github.com/letsencrypt/boulder"

echo "Fetching ${BOULDER_REPO}"
go get -d github.com/letsencrypt/boulder
echo "Retrieved boulder repository"
cd "${GOPATH}/src/${BOULDER_REPO}"
docker-compose up
