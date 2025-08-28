#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

IMAGE=""
TAG=""

if [[ -n $ASSISTED_MCP_IMG ]]; then
    IMAGE=$(echo $ASSISTED_MCP_IMG | cut -d ":" -f1)
    TAG=$(echo $ASSISTED_MCP_IMG | cut -d ":" -f2)
else
    NEWEST_TAG=""
    NEWEST_DATE=0

    TAGS=$(curl -Lf https://quay.io/v2/redhat-services-prod/assisted-installer-tenant/saas/assisted-service-mcp/tags/list | jq -r '.tags[]'|grep -v sha256)
    for TAG in $TAGS; do
        if [[ "${#TAG}" == "7" ]]; then
            MANIFEST=$(curl -Lf "https://quay.io/v2/redhat-services-prod/assisted-installer-tenant/saas/assisted-service-mcp/manifests/$TAG" | jq -r '.history[0].v1Compatibility')
            CREATED_DATE=$(echo "$MANIFEST" | jq -r '.created' | xargs -I {} date -d {} +%s)
            
            if [[ $CREATED_DATE -gt $NEWEST_DATE ]]; then
                NEWEST_DATE=$CREATED_DATE
                NEWEST_TAG=$TAG
            fi
        fi
    done
    IMAGE="quay.io/redhat-services-prod/assisted-installer-tenant/saas/assisted-service-mcp"
    if [[ -z "$NEWEST_TAG" ]]; then
        echo "Unable to resolve the newest 7-char tag from quay.io"
        exit 1
    fi
    TAG=$NEWEST_TAG
fi

oc process -p IMAGE=$IMAGE -p IMAGE_TAG=$TAG -f template.yaml --local | oc apply -n $NAMESPACE -f -

sleep 5
if ! oc rollout status  -n $NAMESPACE deployment/assisted-service-mcp --timeout=300s; then
    echo "Deploying assisted-chat-mcp failed, the logs of the pods are in artifacts/eval-test/gather-extra/artifacts/pods/ directory."
    exit 1
fi