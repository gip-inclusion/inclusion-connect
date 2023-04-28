#!/bin/bash -l

git clone "$IC_SECRETS_HTTPS_REPO_URL" secrets-vault
sops -d secrets-vault/c5/"$IC_ENVIRONMENT".enc.env > .env
