#!/bin/bash
set -e

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check if Dockerfile exists
if [ ! -f "Dockerfile" ]; then
    echo "Error: Dockerfile not found in project root"
    exit 1
fi

echo "Building binary (statically linked for distroless image)..."
# Build with CGO_ENABLED=0 to ensure static linking for distroless image
CGO_ENABLED=0 make build

# Check if binary exists
if [ ! -f "dist/linux_amd64/baton-argo-cd" ]; then
    echo "Error: Binary not found at dist/linux_amd64/baton-argo-cd"
    echo "Please run 'make build' first"
    exit 1
fi

echo "Copying binary for Docker build..."
cp dist/linux_amd64/baton-argo-cd ./baton-argo-cd

# Ensure binary is executable
chmod +x ./baton-argo-cd

# Verify binary is executable and has correct architecture
echo "Verifying binary..."
file ./baton-argo-cd
ls -lh ./baton-argo-cd
echo "Binary modification time: $(stat -c %y ./baton-argo-cd 2>/dev/null || stat -f %Sm ./baton-argo-cd 2>/dev/null || echo 'unknown')"

echo "Building Docker image..."
echo "Image build time: $(date)"
docker build -t baton-argo-cd:latest -f Dockerfile .
echo "Docker image built successfully"

# Note: Can't verify distroless image contents (no shell), but build should succeed if binary exists

echo "Cleaning up copied binary..."
rm -f ./baton-argo-cd

echo "Removing old image from MicroK8s (if exists)..."
microk8s ctr image rm baton-argo-cd:latest 2>/dev/null || true

echo "Importing new image to MicroK8s..."
docker save baton-argo-cd:latest | microk8s ctr image import -

echo "Verifying image was imported..."
microk8s ctr image list | grep baton-argo-cd || echo "Warning: Image not found in MicroK8s"

echo "Deploying to Kubernetes..."
kubectl apply -k k8s/

echo "Deleting existing pods to force recreation with new image..."
kubectl delete pod -n argocd -l app=baton-argo-cd --ignore-not-found=true

echo "Waiting for new pod to be created..."
sleep 5

echo "Waiting for deployment..."
kubectl rollout status deployment/baton-argo-cd -n argocd --timeout=120s || true

echo ""
echo "Checking pod status..."
kubectl get pods -n argocd -l app=baton-argo-cd

echo ""
echo "Recent logs:"
kubectl logs -n argocd -l app=baton-argo-cd --tail=50 || echo "No logs available yet"

echo ""
echo "Deployment complete! To view logs:"
echo "  kubectl logs -n argocd -l app=baton-argo-cd -f"

