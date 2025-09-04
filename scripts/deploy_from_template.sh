#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

IMAGE=""
TAG=""

if [[ -n $ASSISTED_MCP_IMG ]]; then
     echo "The variable ASSISTED_MCP_IMG was proided with the value ${ASSISTED_MCP_IMG}, using it to create the IMAGE and TAG variables for the template"
    IMAGE=$(echo $ASSISTED_MCP_IMG | cut -d ":" -f1)
    TAG=$(echo $ASSISTED_MCP_IMG | cut -d ":" -f2)
else
    IMAGE=quay.io/redhat-user-workloads/assisted-installer-tenant/assisted-service-mcp-saas-main/assisted-service-mcp-saas-main
    echo "The variable ASSISTED_MCP_IMG was not provieded, downloading the latest image from ${IMAGE}"
    TAG="latest"
fi

oc process -p IMAGE=$IMAGE -p IMAGE_TAG=$TAG -p INVENTORY_URL="https://api.stage.openshift.com/api/assisted-install/v2" -f template.yaml --local | oc apply -n $NAMESPACE -f -

sleep 5
if ! oc rollout status  -n $NAMESPACE deployment/assisted-service-mcp --timeout=300s; then
    echo "Deploying assisted-chat-mcp failed, the logs of the pods are in artifacts/eval-test/gather-extra/artifacts/pods/ directory."
    exit 1
fi