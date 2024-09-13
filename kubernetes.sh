GITHUB-TOKEN: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
ghrancher: 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
docker login ghcr.io -u ondrej337 -p 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
docker build -t ghcr.io/ondrej337/postgres/postgres-plpython3u:16.3 .
docker push ghcr.io/ondrej337/postgres/postgres-plpython3u:16.3
---------DBIMPORT:
pg_dump -h localhost -p 5432 -U postgres -d doma -f '/root/kubernetes/postgres/doma-db/db_dump/doma_pg_dump.sql'
pg_dump -h localhost -p 5432 -U postgres -d doma -F c -f doma_pg_dump.dump
pg_restore -h localhost -p 30884 -U postgres -d doma -F c doma_pg_dump.dump
pg_restore -h localhost -p 30884 -U postgres  -C -d doma doma_pg_dump.dump
psql -h localhost -p 30884 -U postgres -d doma -f '/root/kubernetes/postgres/doma-db/db_dump/doma_pg_dump.sql'

--CILIUM---
helm repo add cilium https://helm.cilium.io/
alebo 
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}

curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--flannel-backend=none --disable-network-policy' sh -

# toto netreba zatial
cilium install --version 1.16.1
cilium status --wait
cilium hubble enable
cilium hubble enable --ui

#CILIUM GATEWAY PREREQUISITIES
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.1.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml

#CILIUM API-GATEWAY:
cilium install --version 1.16.1 --set kubeProxyReplacement=true --set gatewayAPI.enabled=true --set hubble.relay.enabled=true --set hubble.ui.enabled=true

k describe GatewayClass cilium

# CILIUM toto instaluj:
------CILIUM + INGRESS install + hubble/ui enable
cilium install --version 1.16.1 --set kubeProxyReplacement=true --set ingressController.enabled=true  \
              --set ingressController.loadbalancerMode=shared --set hubble.relay.enabled=true --set hubble.ui.enabled=true

ak chces dedikovany: https://docs.cilium.io/en/latest/network/servicemesh/ingress/ (zatial mi to nefungovalo)
cilium install --version 1.16.1 --set kubeProxyReplacement=true --set l7Proxy=true --set nodePort.enabled=true --set ingressController.enabled=true --set ingressController.loadbalancerMode=dedicated

$ kubectl -n kube-system rollout restart deployment/cilium-operator
$ kubectl -n kube-system rollout restart ds/cilium

cilium connectivity test --request-timeout 30s --connect-timeout 10s
# INGRES CHECK:
k create ns demo
kubectl create deployment demo --image=nginx --port=80
kubectl expose deployment demo
kubectl create ingress demo --class=cilium   --rule nginx.koval.top/=demo:80 --dry-run -o yaml

-- CERT MANAGER:
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set crds.enabled=true

ako dalej navod:
https://github.com/ChristianLempa/boilerplates/tree/main/kubernetes/certmanager
https://www.youtube.com/watch?v=DvXkD0f-lhY

cloudflareApi: e7460646cf187557be8b08ff998cde778900e

--Wildcard cert letsencrypt for domain koval.top
https://docs.digitalocean.com/products/kubernetes/getting-started/operational-readiness/configure-wildcard-certificates/
DNS domain koval.top is on cloudflare.com
Copy api key from cloudflare
k create ns koval-top
-> go to kubernetes/certs
k apply -f secret-cloudflare.yaml
k apply -f clusterissuer-wcard-acme.yaml
kubectl get ClusterIssuer -n cert-manager
k apply -f cert-wcard-koval-top.yaml
k describe certificate
=> OK => Normal  Issuing    12m   cert-manager-certificates-issuing          The certificate has been successfully issued
k get certificaterequest  (pozri READY/APPROVED - TRUE)
k get certificate   
Ingress:
go to kubernetes/web/koval-top
k apply -f koval-top.yaml
-- test web:
curl -Li https://koval.top/
#DUPLICATE CERT
helm repo add emberstack https://emberstack.github.io/helm-charts
helm repo update
helm upgrade --install reflector emberstack/reflector


#get all certmanager
kubectl get Issuers,ClusterIssuers,Certificates,CertificateRequests,Orders,Challenges --all-namespaces -o wide

k3sup install --k3s-channel v1.27.16-rc1+k3s1 --k3s-extra-args '--disable traefik --tls-san=postgres.brestova.eu' --ip 10.10.10.11 --user root --cluster --local-path=./.kube/config
Extend the cluster (masters)
k3sup join --k3s-channel v1.27.16-rc1+k3s1 --k3s-extra-args '--disable traefik --tls-san=postgres.brestova.eu' --ip 10.10.10.12 --user root --server-user root --server-ip 10.10.10.11  --server
k3sup join --k3s-channel v1.27.16-rc1+k3s1 --k3s-extra-args '--disable traefik --tls-san=postgres.brestova.eu' --ip 10.10.10.13 --user root --server-user root --server-ip 10.10.10.11  --server
create user: adduser ondrej
sudo visudo
ondrej ALL=(ALL) NOPASSWD: ALL

NETWORK PRIVATE:
debian: /etc/network/interfaces
auto eth1
iface eth1 inet static 
  address 10.10.10.13
  netmask 255.255.255.0

systemctl restart networking


k3sup install  --k3s-extra-args '--disable traefik --tls-san=postgres.brestova.eu' --ip 10.10.10.11 --user ondrej --cluster --local-path=./.kube/config
k3sup join --k3s-extra-args "--disable traefik --tls-san=postgres.brestova.eu" --ip 10.10.10.12 --user ondrej --server-user ondrej --server-ip 10.10.10.11  --server


----MASTER+AGENT
Master:
k3sup install  --k3s-extra-args '--disable traefik --tls-san=postgres.brestova.eu' --ip 10.10.10.11 --user ondrej --local-path=./.kube/config
AGENT:
k3sup join --ip 10.10.10.12 --user ondrej --server-user ondrej --server-ip 10.10.10.11
UNINSTALL:
/usr/local/bin/k3s-uninstall.sh
Agent node:
/usr/local/bin/k3s-agent-uninstall.sh


dbnode1=>94.16.108.18
dbnode2=>89.58.4.135
dbnode3=>94.16.110.225

install kubectl:
https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
kubectx:
https://github.com/ahmetb/kubectx
sudo git clone https://github.com/ahmetb/kubectx /opt/kubectx
sudo ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx
sudo ln -s /opt/kubectx/kubens /usr/local/bin/kubens

helm:
https://helm.sh/docs/intro/install/
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
$ chmod 700 get_helm.sh
$ ./get_helm.sh

--NGINX ingressController----
nginx controler:https://kubernetes.github.io/ingress-nginx/deploy/

--standard
helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --namespace ingress-nginx --create-namespace

helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --set controller.config.use-proxy-protocol=true \
  --namespace ingress-nginx --create-namespace

helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --set controller.service.externalTrafficPolicy=Local \
  --set controller.config.use-proxy-protocol=true \
  --namespace ingress-nginx --create-namespace

# INGRES CHECK:
k create ns demo
kubectl create deployment demo --image=httpd --port=80
kubectl expose deployment demo
kubectl create ingress demo-k3sk --class=nginx   --rule k3s.brestova.eu/=demo:80


# Longhorn:

# Installation Requirements
https://longhorn.io/docs/1.6.2/deploy/install/#installation-requirements
curl -sSfL https://raw.githubusercontent.com/longhorn/longhorn/v1.6.2/scripts/environment_check.sh | bash
# DEBIAN 12:
apt install nfs-common open-iscsi cryptsetup
# Add repo to helm:
helm repo add longhorn https://charts.longhorn.io
helm repo update
# Install longhorn:
helm install longhorn longhorn/longhorn --namespace longhorn-system --create-namespace --version 1.7.1

RANCHER:
helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
helm repo update
kubectl create namespace cattle-system
helm install rancher rancher-stable/rancher --namespace cattle-system --set hostname=rancher.koval.top --set bootstrapPassword=admin
heslo:
kubectl get secret --namespace cattle-system bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}{{"\n"}}'

k port-forward -n cattle-system service/rancher  --address 0.0.0.0 8000:443
DNS:
https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/
kubectl apply -f https://k8s.io/examples/admin/dns/dnsutils.yaml
kubectl exec -i -t dnsutils -- nslookup kubernetes.default
kubectl exec -i -t dnsutils -n default -- nslookup ecp-db-cluster-rw.cloudnative-pg
kubectl exec -i -t dnsutils -n default -- nslookup ecp-db-broker-cluster-rw.cloudnative-pg

Postgres
IMAGES:
https://github.com/cloudnative-pg/postgres-containers
plugin treba update:
    curl -sSfL \
  https://github.com/cloudnative-pg/cloudnative-pg/raw/main/hack/install-cnpg-plugin.sh | \
  sudo sh -s -- -b /usr/local/bin

#Installing the Operator:  
helm repo add cnpg https://cloudnative-pg.github.io/charts

helm upgrade --install cnpg \
--namespace cnpg-system \
--create-namespace \
cnpg/cloudnative-pg 

alebo najnovsia verzia:
    
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/releases/cnpg-1.24.0.yaml

kubectl create ns cloudnative-pg

CNPG commands:
https://cloudnative-pg.io/documentation/1.20/kubectl-plugin/
curl -sSfL \
  https://github.com/cloudnative-pg/cloudnative-pg/raw/main/hack/install-cnpg-plugin.sh | \
  sudo sh -s -- -b /usr/local/bin

storage/disk
PV predstavuje fyzický úložný priestor v klustri, zatiaľ čo PVC je požiadavka na tento úložný priestor
PV je úložný zdroj v klustri, ktorý môže byť staticky alebo dynamicky provisionovaný administrátorom

PVC špecifikuje požiadavky na úložisko, ako je veľkosť, prístupový režim a trieda úložiska.
Kubernetes použije PVC na nájdenie dostupného PV, ktorý spĺňa požiadavky PVC.
k get pvc -o wide
k get pv -o wide
/var/lib/kubelet/pods/5fa7e209-9d46-42cf-bca7-2304d769ced2/volumes/kubernetes.io~csi/pvc-adda9885-c89b-4283-bc41-0cdceca8cad8/mount
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                   STORAGECLASS   VOLUMEATTRIBUTESCLASS   REASON   AGE   VOLUMEMODE
pvc-fa4ee815-7d0b-44a4-bfd8-9abccbcc79b7   1Gi        RWO            Delete           Bound    cloudnative-pg/mydb-2   longhorn       <unset>                          97m   Filesystem
pvc-adda9885-c89b-4283-bc41-0cdceca8cad8   1Gi        RWO            Delete           Bound    cloudnative-pg/mydb-1   longhorn       <unset>                          99m   Filesystem
pvc-602eb312-3b22-4f16-a35f-f0f0a0bc0988   1Gi        RWO            Delete           Bound    cloudnative-pg/mydb-3   longhorn       <unset>                          96m   Filesystem

kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: longhorn-postgres-storage
  annotations:
    storageclass.kubernetes.io/is-default-class: "false"
provisioner: driver.longhorn.io
allowVolumeExpansion: true
# WaitForFirstConsumer mode will delay the binding and provisioning of a PersistentVolume until a Pod using the PersistentVolumeClaim is created.
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
parameters:
  numberOfReplicas: "1"
  staleReplicaTimeout: "1440" # 1 day
  fsType: "ext4"
  diskSelector: "nvme"
  dataLocality: "strict-local"
  
  CHARTS:
  https://github.com/cloudnative-pg/charts/tree/main/charts/cluster
  images: https://github.com/cloudnative-pg/postgres-containers/blob/main/Debian/ClusterImageCatalog-bullseye.yaml
  
  Cluster:
  helm repo add cnpg https://cloudnative-pg.github.io/charts
  
helm upgrade --install ecp-db \
--namespace cloudnative-pg \
--create-namespace \
--values values.yaml \
cnpg/cluster

helm upgrade --install ecp-db-broker \
--namespace cloudnative-pg \
--create-namespace \
--values values.yaml \
cnpg/cluster

helm upgrade --install edx-db \
--namespace cloudnative-pg \
--create-namespace \
--values values.yaml \
cnpg/cluster


helm uninstall ecp-db \
--namespace cloudnative-pg 

helm uninstall ecp-db-broker \
--namespace cloudnative-pg 

helm uninstall edx-db \
--namespace cloudnative-pg 




--latest manifest:
https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/releases/cnpg-1.24.0.yaml

secretName
apiVersion: v1
kind: Secret
metadata:
  name: ep1-secret
  namespace: cloudnative-pg
  labels:
    cnpg.io/reload: "true"
type: kubernetes.io/basic-auth
data:
	username: ZXAxCg==
	password: cGFzc3dvcmQK

NGINX:
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: example
    namespace: foo
  spec:
    ingressClassName: nginx
    rules:
      - host: www.example.com
        http:
          paths:
            - pathType: Prefix
              backend:
                service:
                  name: exampleService
                  port:
                    number: 80
              path: /
    # This section is only required if TLS is to be enabled for the Ingress
    tls:
      - hosts:
        - www.example.com
        secretName: example-tls

If TLS is enabled for the Ingress, a Secret containing the certificate and key must also be provided:

  apiVersion: v1
  kind: Secret
  metadata:
    name: example-tls
    namespace: foo
  data:
    tls.crt: <base64 encoded cert>
    tls.key: <base64 encoded key>
  type: kubernetes.io/tls
  
  
  NGINX LOADBALANCER:
  almalinux install:
  dnf install nginx-mod-stream
  
  a za event{}
  zadaj:
  
  stream {
  	upstream k3s_servers {
    	server 94.16.108.18:6443; # Change to the IP of the K3s first master VM
    	server 89.58.4.135:6443; # Change to the IP of the K3s second master VM
  		}
	server {
		listen 6443;
		proxy_pass k3s_servers;
	}
  }

alebo s privatnou ip
stream {
  	upstream k3s_servers {
    	server 10.10.10.11:6443; # Change to the IP of the K3s first master VM
    	server 10.10.10.12:6443; # Change to the IP of the K3s second master VM
  		}
	server {
		listen 6443;
		proxy_pass k3s_servers;
	}
  }
  
  
  
  
  NGINX LOADBALANCER:
  almalinux install:
  dnf install nginx-mod-stream
  
  a za event{}
  zadaj:
  
  stream {
  	upstream k3s_servers {
    	server 94.16.108.18:6443; # Change to the IP of the K3s first master VM
    	server 89.58.4.135:6443; # Change to the IP of the K3s second master VM
  		}
	server {
		listen 6443;
		proxy_pass k3s_servers;
	}
  }

alebo s privatnou ip
stream {
  	upstream k3s_servers {
    	server 10.10.10.11:6443; # Change to the IP of the K3s first master VM
    	server 10.10.10.12:6443; # Change to the IP of the K3s second master VM
  		}
	server {
		listen 6443;
		proxy_pass k3s_servers;
	}
  }

ECCOSP:
  helm template ecp ecco-sp -f ecco-sp/values-ecp11.yaml > temp-ecp-value.yaml -n eccosp
  helm template edx ecco-sp -f ecco-sp/values-edx11.yaml > temp-edx-value.yaml -n eccosp
  k apply -f temp-ecp-value.yaml
  k apply -f temp-edx-value.yaml
  k edit ing eccosp-ecp-endpoint-ep1-ingress
  k edit ing eccosp-edx-toolbox-tb1-ingress
  ingressClassName: nginx
  k describe po eccosp-ecp-endpoint-ep1-0
  k3s ctr images ls
  ctr images import ecp-endpoint-4.12.0.1871.tar
 
 k cp eccosp-ecp-endpoint-ep1-0:/var/lib/ecp-endpoint/authKeystore.jks authKeystore.jks
 k cp authKeystore.jks eccosp-edx-toolbox-tb1-0:/var/lib/edx-toolbox/authKeystore.jks
 k cp eccosp-ecp-endpoint-ep1-1:/var/lib/ecp-endpoint/authKeystore.jks authKeystore.jks
 k cp authKeystore.jks eccosp-edx-toolbox-tb1-1:/var/lib/edx-toolbox/authKeystore.jks
 k cp eccosp-ecp-endpoint-ep1-2:/var/lib/ecp-endpoint/authKeystore.jks authKeystore.jks
 k cp authKeystore.jks eccosp-edx-toolbox-tb1-2:/var/lib/edx-toolbox/authKeystore.jks

ECCOSP-CILIUM:
  helm template ecp ecco-sp -f ecco-sp/values-ecp-cilium.yaml > temp-ecp-value.yaml -n eccosp
  helm template edx ecco-sp -f ecco-sp/values-edx11.yaml > temp-edx-value.yaml -n eccosp
  k apply -f temp-ecp-value.yaml
  k apply -f temp-edx-value.yaml
  k edit ing eccosp-ecp-endpoint-ep1-ingress
  k edit ing eccosp-edx-toolbox-tb1-ingress
  ingressClassName: cilium

ECCO-SP:
#  helm template ecp ecco-sp -f ecco-sp/values-ecp1.yaml > temp-ecp-value.yaml -n ecco-sp
#  helm template edx ecco-sp -f ecco-sp/values-edx1.yaml > temp-edx-value.yaml -n ecco-sp
#  k apply -f temp-ecp-value.yaml
#  k apply -f temp-edx-value.yaml
#  k edit ing ecco-sp-ecp-endpoint-ep1-ingress
#  k edit ing ecco-sp-edx-toolbox-tb1-ingress
#  ingressClassName: nginx
#  k describe po eccosp-ecp-endpoint-ep1-0
  k3s ctr images ls
  ctr images import ecp-endpoint-4.12.0.1871.tar
 
 k cp ecco-sp-ecp-endpoint-ep1-0:/var/lib/ecp-endpoint/authKeystore.jks authKeystore.jks
 k cp authKeystore.jks ecco-sp-edx-toolbox-tb1-0:/var/lib/edx-toolbox/authKeystore.jks

 tls-rancher-koval-top


 
 