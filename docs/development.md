# Développer sur Inclusion Connect

## Prérequis

Pour développer sur Inclusion Connect, il vous faudra un ordinateur avec les logiciels suivants:
- python3
- make
- git
- docker
- docker-compose

## Cloner le dépôt GitHub

```sh
git clone git@github.com:gip-inclusion/inclusion-connect.git
```

## Installer les dépendances

Nous vous conseillons l'utilisation d'un environnement virtuel pour gérer les dépendances. Libre à vous de gérer vos environnements virtuels comme vous le souhaitez, dans cette documentation nous créerons un [environnement virtuel comme stipulé dans la documentation officielle de python](https://docs.python.org/3/library/venv.html) dans un répertoire `.venv`.


### Créer un environnement virtuel & installer les dépendances

```sh
make venv
```

Cette commande va créer un environnement virtuel dans `.venv`, installer les dépendances via `pip install` et s'assurer qu'elles sont toujours à jour via [`pip-sync`](https://github.com/jazzband/pip-tools).

### Activer l'environnement virtuel

Avant chaque commande python/django, assurez-vous d'avoir un environnement virtuel d'activé au préalable. Pour activer un environnement virtuel pour le shell courant, lancez la commande suivante :

```sh
. .venv/bin/activate
```

## Démarrer PostgreSQL et MailHog

Lancer les images dockers depuis la racine du dépôt :

```bash
docker compose up
```


## Charger les données par défaut et configurer le service

La première fois que vous lancez le service, il faudra configurer Inclusion Connect en chargeant les données par défaut dans la base (soyez certain que votre virtualenv est bien activé) :

```
./manage.py migrate
make populate_db
```

## Générer une clé RSA

Cette clé sera utilisée pour signer les jwt renvoyés aux partenaires.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out oidc.pem
```

## Lancer le serveur de développement

Avec votre environnement virtuel d'activé lancez :

```sh
make runserver
```

## Lancer les tests

```sh
make test
```

## Normalement tout devrait être bon !

Si tout va bien (croisons les doigts) vous aurez accès à l'admin : [http://localhost:8080/admin](http://localhost:8080/admin) et aux [autres urls](docs/inclusion_connect.md).

Il faudra également surcharger les `redirect_uris` par défaut de l'application via l'administration Django.

> [!NOTE]
> Pour accéder à l'admin, les informations de connexion sont les suivantes :
> - Adresse e-mail : `admin@test.com`
> - Mot de passe : `password`
>
> Pour utiliser le service et se connecter avec un client OpenID Connect, il vous faudra les identifiants suivants :
> - le `client_id` est `local_inclusion_connect`
> - le `client_secret` est `password`


# Composants applicatifs

## Base de données PostgreSQL

Inclusion Connect utilise une base de données PostgreSQL.

C'est le fichier ``docker-compose.yml`` qui s'occupe de tout pour créer celle-ci.

NB : le port exposé est le `5433` car si vous travaillez déjà avec un PSQL, il est probable que votre port `5432` soit déjà utilisé.

## Serveur mail de test MailHog

Afin d'avoir accès aux mails envoyés par Inclusion Connect en local, notre `docker-compose.yml` lance une image docker de [MailHog](https://github.com/mailhog/MailHog).

MailHog donne accès à un faux webmail à l'adresse http://localhost:8025 qui permet d'afficher tous les emails qui sont envoyés.
Cela permet de ne pas avoir besoin d'un vrai serveur SMTP et d'une vraie adresse email.
