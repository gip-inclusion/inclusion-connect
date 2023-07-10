#!/bin/bash

export BACKUP_FILE=backup.dump
if [ `type -t scalingo`"" != 'file' ]; then
  echo -e "\n>> Installing scalingo CLI"
  # https://doc.scalingo.com/platform/cli/start
  curl -O https://cli-dl.scalingo.com/install && bash install
fi


echo -e "\n>> Importing psql dump from Scaleway"
# TODO when Django is deployed on prod use real backups
scalingo --app $SCALINGO_APP_NAME db-tunnel $SCALINGO_POSTGRESQL_URL --port 10000 &
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
