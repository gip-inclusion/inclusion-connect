#!/bin/bash

export BACKUP_FILE=backup.dump
# FIXME: change to main (or remove)
export GIT_BRANCH=alaurent/scalingo_failover
export ENV_FILE=SCALINGO_FAILOVER.env

echo "\n>> Loading environment variables from SCALINGO_FAILOVER.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "/!\ Missing env file. Decrypt c5.SCALINGO_FAILOVER.enc.env file in private secret repository."
    exit
fi
eval $(cat SCALINGO_FAILOVER.env)

if [ `type -t scalingo`"" != 'file' ]; then
  echo -e "\n>> Installing scalingo CLI"
  # https://doc.scalingo.com/platform/cli/start
  curl -O https://cli-dl.scalingo.com/install && bash install
fi

echo -e "\n>> Synchronizing ${GIT_BRANCH} branch"
git fetch origin
git checkout $GIT_BRANCH
git rebase origin/${GIT_BRANCH} $GIT_BRANCH

echo -e "\n>> Pushing code to $ scalingo app"
git push $SCALINGO_GIT_URL ${GIT_BRANCH}:main --force

echo -e "\n>> Importing psql dump from Scaleway"
# TODO when Django is deployed on prod use real backups
scalingo --app $SCALINGO_APP_NAME db-tunnel $SCALINGO_POSTGRESQL_URL &
pid=$!
sleep 2
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --no-comments \
  --dbname $SCALINGO_DB_TUNNEL_URL \
  $BACKUP_FILE
kill $pid

echo -e "\n>> Scale up web to 1 instance"
scalingo scale --app $SCALINGO_APP_NAME web:1

echo -e "\n>> Go mannually swap DNS in alwaysdata"
python -m webbrowser $ALWAYSDATA_URL

# echo -e "\n>> Increase Scalingo PSQL plan"
# scalingo --app $SCALINGO_APP_NAME addons-upgrade XXX postgresql-sandbox

# Whenver clever cloud is back online :
# - dump back data
# - scale to 0 to disable application
# - reverse alwaysdata DNS
# - revert addon upgrade back to postgresql-sandbox
