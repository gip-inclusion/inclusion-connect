#!/bin/bash -l

cd secrets-vault || exit
git pull
cd - || exit
sops -d secrets-vault/c5/"$IC_ENVIRONMENT".enc.env > .env
