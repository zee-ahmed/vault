#!/bin/bash

. vault.env

exec vault server -dev -dev-root-token-id=${VAULT_TOKEN} -dev-listen-address="0.0.0.0:8200" -log-level="debug"
