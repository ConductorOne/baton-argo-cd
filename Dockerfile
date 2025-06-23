FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-argo-cd"]
COPY baton-argo-cd /