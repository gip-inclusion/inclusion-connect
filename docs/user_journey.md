# Parcours utilisateur sur Inclusion Connect

Ce document liste les différents parcours utilisateurs.

Vous trouverez à chaque fois un lien (pour un environnement local) afin d’entrer sur le parcours et pouvoir le tester.

Les URLs de retour sont configurées pour un setup local des emplois de l’inclusion. Cela fonctionne également sans avoir ce setup, vous finirez juste sur une page “Unable to connect”


## Parcours de connexion

- <details>
  <summary>1) Arrivée sur la page de connexion</summary>

  ![image info](img/login-1.jpg)

  - <details>
    <summary>**[DEV]** : Url et paramètres d’accès direct à la page:</summary>

    http://0.0.0.0:8080/auth/authorize?response_type=code&client_id=local_inclusion_connect&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Finclusion_connect%2Fcallback&scope=openid+profile+email&state=0xGVKT6eO9NT%3Aarn7NqGqozXjsvio5CAmU2lpoF2nJmLTlU9OuaHAtOg&nonce=r04v4u8sT05W

    L’url est celle de l’endpoint Authorization: `https://{hostname}/auth/authorize`

    Les paramètres à renseigner sont:

    - `**response_type**` : La valeur `code`
    - `**client_id**` : Le `CLIENT_ID` qui vous été fourni
    - `**redirect_uri**` : L’url à laquelle sera redirigée l’utilisateur à la fin du processus sur Inclusion Connect
    - `**scope**` : La valeur `openid profile email`
    - `**state**` : Une valeur généré par votre application ([voir documentation sur github pour plus de détail](inclusion_connect.md#requête-authentification))
    - `**nonce**` : Une autre valeur généré par votre application ([voir documentation sur github pour plus de détail](inclusion_connect.md#requête-authentification))
    - `**login_hint**` (optionnel) : permet de spécifier l'adresse e-mail que l'utilisateur doit utiliser pour se connecter ou pour se créer un compte.

  </details>

</details>

- <details>
  <summary>2) L’utilisateur saisit son login/mdp, clique sur “Se connecter” et est redirigé vers la plateforme depuis laquelle il est parti</summary>
</details>

## Déconnexion en passant par la page Inclusion Connect

La déconnexion peut être faite de deux manières:

- <details>
  <summary>soit transparente (l’utilisateur ne voit pas Inclusion Connect)</summary>

  - <details>
    <summary>**[DEV]** : Url et paramètres d’accès direct à la page:</summary>

    Pas d’accès direct vu qu’il faut l’`id_token`

    L’url est celle de l’endpoint Logout: `https://{hostname}/auth/logout`

    Les paramètres à renseigner sont:

    - `**id_token_hint**` : l’`id_token` récupéré à l’étape de connexion de l’utilisateur
    - `**post_logout_redirect_uri**` : L’url à laquelle sera redirigée l’utilisateur après avoir été déconnecté

  </details>

</details>

- <details>
  <summary>soit en affichant la page de déconnexion d’Inclusion Connect</summary>

  ![image info](img/logout-prompt.jpg)

  - <details>
    <summary>**[DEV]** : Url et paramètres d’accès direct à la page:</summary>

    http://0.0.0.0:8080/auth/logout?client_id=local_inclusion_connect&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8000

    L’url est celle de l’endpoint Logout: `https://{hostname}/auth/logout`

    Les paramètres à renseigner sont:

    - `**client_id**` : Le `CLIENT_ID` qui vous été fourni
    - `**post_logout_redirect_uri**` : L’url à laquelle sera redirigée l’utilisateur àprès avoir été decconecté

  </details>

</details>
