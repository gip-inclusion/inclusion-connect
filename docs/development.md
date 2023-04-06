# Développer sur Inclusion Connect

## Prérequis

Pour développer sur Inclusion Connect, il vous faudra un ordinateur avec les logiciels suivants:
- git
- docker

## Cloner le dépôt GitHub

La première étape est de cloner le dépôt sur votre ordinateur.

## Base de données

Inclusion Connect utilise une base de données PostgreSQL.

C'est le fichier ``docker-compose.yml`` qui s'occupe de tout pour créer celle-ci.

NB: le port exposé est le `5433` car si vous travaillez déjà avec un PSQL, il est probable que votre port
`5432` soit déjà utilisé.

## Serveur mail de test

Afin d'avoir accès aux mails envoyés par Inclusion Connect en local, notre `docker-compose.yml` lance une image docker de [MailHog](https://github.com/mailhog/MailHog).

MailHog donne accès à un faux webmail à l'addresse http://0.0.0.0:8025 qui permet d'afficher tous les emails qui sont envoyés.
Cela permet de ne pas avoir besoin d'un vrai serveur SMTP et d'une vraie adresse email.

## Variables d'environnement

/!\ A RE-ECRIRE

## Lancer le service en local

Il ne reste plus qu'à lancer les images dockers depuis la racine du dépôt :

```bash
docker-compose up
```

## Configuration du service

La première fois que vous lancez le service, il faudra configurer Inclusion Connect

```
./manage.py migrate
make populate_db
```

Il faudra également surcharger les redirect_uris de l'application créée dans les fixtures

Pour utiliser le service il faut les identifiantes suivants :
- le `client_id` est `local_inclusion_connect`
- le `client_secret` est `password`

## Normalement tout est bon !

Si tout va bien (croisons les doigts) vous aurez accès à l'admin : `http://0.0.0.0:8080/admin`
et aux autres urls.

Il faudra utiliser le couple `local_inclusion_connect`/`password` comme indiqué précédement pour se connecter avec un client OpenID Connect

## En cas de soucis

### La base de données est mal initialisée

Rencontré typiquement si les variables d'environnement sont mal configurée, il faudra :
/!\ A RE-ECRIRE
