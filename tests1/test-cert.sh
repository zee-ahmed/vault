set -e 

# VAULT_TOKEN=${COMING FROM XX}
# VAULT_ADDR=http://vault.jetstack.internal:8200

# generate new key if needeed
test -e key.pem || { openssl genrsa -out key.pem 2048 && rm -f csr.pem cert.pem; }

# generate new csr if needeed
test -e csr.pem || { openssl req -new -key key.pem -out csr.pem -subj '/CN=etcd1.test.internal' && rm -f cert.pem; }

# renew my token
vault token-renew

vault write --field certificate k8s-dev/pki/etcd-k8s/sign/server csr="$(cat csr.pem)" > cert.pem
