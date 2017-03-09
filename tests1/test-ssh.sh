#!/bin/bash

. vault.env

vault mount -path=test-ssh ssh
vault write test-ssh/keys/test_key key=@id_rsa
