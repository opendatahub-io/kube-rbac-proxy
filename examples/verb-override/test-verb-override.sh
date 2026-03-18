#!/bin/bash

# Test script for verb-override functionality
# This script demonstrates that the verb override works regardless of HTTP method

set -euo pipefail

echo "=== Testing kube-rbac-proxy verb override functionality ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color="${1}"
    local message="${2}"
    echo -e "${color}${message}${NC}"
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_status "${RED}" "kubectl not found. Please install kubectl and configure access to a Kubernetes cluster."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    print_status "${RED}" "Cannot access Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

print_status "${YELLOW}" "Step 1: Deploying kube-rbac-proxy with verb override configuration..."
kubectl apply -f deployment.yaml

print_status "${YELLOW}" "Step 2: Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/kube-rbac-proxy-verb-override

print_status "${YELLOW}" "Step 3: Deploying client RBAC (with 'list' permission on pods)..."
kubectl apply -f client-rbac.yaml

print_status "${YELLOW}" "Step 4: Testing with GET request..."
kubectl apply -f client.yaml

# Wait for job to complete
kubectl wait --for=condition=complete --timeout=60s job/krp-curl-verb-override

# Check job logs
print_status "${GREEN}" "GET request test results:"
kubectl logs job/krp-curl-verb-override

print_status "${GREEN}" "Verb override functionality test completed."
print_status "${YELLOW}" "To clean up: kubectl delete -f deployment.yaml -f client-rbac.yaml -f client.yaml"
