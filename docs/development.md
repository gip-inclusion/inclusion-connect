# Développer sur Inclusion Connect

## Prérequis

Pour développer sur Inclusion Connect, il vous faudra un ordinateur avec les logiciels suivants:
- git
- docker
- docker-compose

## Cloner le dépôt GitHub

La première étape est de cloner le dépôt sur votre ordinateur.

# Composants applicatifs

## Base de données PostgreSQL

Inclusion Connect utilise une base de données PostgreSQL.

C'est le fichier ``docker-compose.yml`` qui s'occupe de tout pour créer celle-ci.

NB: le port exposé est le `5433` car si vous travaillez déjà avec un PSQL, il est probable que votre port
`5432` soit déjà utilisé.

## Serveur mail de test MailHog

Afin d'avoir accès aux mails envoyés par Inclusion Connect en local, notre `docker-compose.yml` lance une image docker de [MailHog](https://github.com/mailhog/MailHog).

MailHog donne accès à un faux webmail à l'addresse http://localhost:8025 qui permet d'afficher tous les emails qui sont envoyés.
Cela permet de ne pas avoir besoin d'un vrai serveur SMTP et d'une vraie adresse email.

## Générer une clé RSA

Cette clé sera utilisée pour signer les jwt renvoyés aux partenaires.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out oidc.pem
```

## Démarrer PostgreSQL et MailHog

Lancer les images dockers depuis la racine du dépôt :

```bash
docker compose up
```

## Serveur de développement

```sh
make runserver
```

## Tests

```sh
make test
```

# Configuration du service

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

Si tout va bien (croisons les doigts) vous aurez accès à l'admin : `http://localhost:8080/admin`
et aux autres urls.

Il faudra utiliser le couple `local_inclusion_connect`/`password` comme indiqué précédement pour se connecter avec un client OpenID Connect
