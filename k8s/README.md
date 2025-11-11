# Kubernetes Deployment for Baton Argo CD Connector

# For development

This directory contains Kubernetes manifests to deploy the Baton Argo CD connector alongside Argo CD in the same namespace, enabling in-cluster configuration.

## Prerequisites

- Argo CD running in the `argocd` namespace
- kubectl configured to access your MicroK8s cluster
- Docker image built and available (or use local registry)

## Deployment Steps

Following there is a description of the steps to take. To test, execute the script test-deploy.sh located in <root directory>/baton-argo-cd/scripts/
The scripts assumes the build to be in dist/linux_amd64/baton-argo-cd. 

### 1. Build and Push the Docker Image

```bash
# Build the binary
make build

# Build the Docker image
docker build -t baton-argo-cd:latest .

# For MicroK8s, import the image (or use a local registry)
docker save baton-argo-cd:latest | microk8s ctr image import -
```

Alternatively, if you have a container registry:
```bash
docker tag baton-argo-cd:latest your-registry/baton-argo-cd:latest
docker push your-registry/baton-argo-cd:latest
# Then update the image in deployment.yaml
```

### 2. Create the Secret

Create a secret with your Argo CD credentials:

```bash
kubectl create secret generic baton-argo-cd-secret \
  --from-literal=username=admin \
  --from-literal=password=your-argocd-password \
  -n argocd
```

Or use the example secret file (update with your credentials first):
```bash
kubectl apply -f secret.yaml.example
```

### 3. Deploy the Connector

Apply all manifests:

```bash
kubectl apply -f k8s/
```

Or apply individually:
```bash
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/role.yaml
kubectl apply -f k8s/rolebinding.yaml
kubectl apply -f k8s/deployment.yaml
```

### 4. Verify Deployment

```bash
# Check the deployment
kubectl get deployment baton-argo-cd -n argocd

# Check the pods
kubectl get pods -n argocd -l app=baton-argo-cd

# View logs
kubectl logs -n argocd -l app=baton-argo-cd
```

## Configuration

### In-Cluster Config

When deployed in the `argocd` namespace, the connector automatically uses in-cluster configuration. The code will:
1. First try `rest.InClusterConfig()` (which reads from the pod's service account)
2. If that fails, fall back to kubeconfig file or provided kubeconfig bytes

Since you're deploying in the same namespace, **you don't need to provide a kubeconfig** - the in-cluster config will be used automatically.

### Environment Variables

The deployment uses these environment variables (set in `deployment.yaml`):
- `BATON_API_URL`: Argo CD server URL (defaults to internal service)
- `BATON_USERNAME`: Argo CD username (from secret)
- `BATON_PASSWORD`: Argo CD password (from secret)

### Argo CD API URL

The default API URL in the deployment uses the internal Kubernetes service:
```
https://argocd-server.argocd.svc.cluster.local
```

If you need to use a different URL (e.g., external ingress), update the `BATON_API_URL` environment variable in the deployment.

## Permissions

The connector needs the following permissions in the `argocd` namespace:
- **GET** on `argocd-rbac-cm` ConfigMap (to read RBAC policies)
- **PATCH/UPDATE** on `argocd-rbac-cm` ConfigMap (to update role grants)
- **PATCH/UPDATE** on `argocd-cm` ConfigMap (to create accounts)

These are defined in the `role.yaml` manifest.

## Troubleshooting

### Check Service Account
```bash
kubectl get serviceaccount baton-argo-cd -n argocd
```

### Check Permissions
```bash
kubectl auth can-i get configmaps/argocd-rbac-cm -n argocd --as=system:serviceaccount:argocd:baton-argo-cd
kubectl auth can-i patch configmaps/argocd-rbac-cm -n argocd --as=system:serviceaccount:argocd:baton-argo-cd
```

### View Pod Logs
```bash
kubectl logs -n argocd -l app=baton-argo-cd --tail=100
```

### Describe Pod for Issues
```bash
kubectl describe pod -n argocd -l app=baton-argo-cd
```

## Cleanup

To remove the deployment:

```bash
kubectl delete -f k8s/
```

Or delete individually:
```bash
kubectl delete deployment baton-argo-cd -n argocd
kubectl delete rolebinding baton-argo-cd -n argocd
kubectl delete role baton-argo-cd -n argocd
kubectl delete serviceaccount baton-argo-cd -n argocd
kubectl delete secret baton-argo-cd-secret -n argocd
```

