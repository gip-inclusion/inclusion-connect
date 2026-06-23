# Journal des modifications


## [Non publié]

### Ajouté

- Fournisseur d'identité SAML 2.0 : endpoint de métadonnées IdP dynamique (`GET /saml/metadata`).
- Fournisseur d'identité SAML 2.0 : SSO initié par le SP (`GET /saml/sso`, binding HTTP-Redirect) émettant une assertion signée auto-postée vers l'ACS.
- Réglages `SAML_IDP_ENTITY_ID`, `SAML_IDP_SIGNING_KEY_FILE` et `SAML_IDP_SIGNING_CERT_FILE` (certificat de signature dédié, cycle de vie indépendant de `oidc.pem`).
- Réglage `SAML_XMLSEC1_BINARY` (chemin du binaire `xmlsec1`, sinon détection automatique sur le `PATH`).

### Modifié

- Ajout de la dépendance `pysaml2`, qui plafonne `pyopenssl<24.3.0` et force `cryptography` de 49 à 43.
- La signature des assertions SAML requiert désormais le binaire système `xmlsec1` à l'exécution (à installer en CI et en production).


## [2] - 2023-07-17

### Ajouté

- Prise en compte du login_hint quand l'utilisateur arrive pour changer ses informations personnelles.
- Landing page

### Modifié

- Mise à jour du thème

## [1] - 2023-06-27

### Ajouté

- Refonte Django des fonctionnalités de Keycloak utilisées.
- Envoi des logs dans Elasticsearch.
- Ajout de statistiques de connexion.
- Mise en place d'une script de migration depuis Keycloak.
- Permettre la validation d'adresse e-mail depuis un autre navigateur.
- La formulation de la page d'activation de compte dépend de l'application partenaire.
- Accepter les CGAUs à l'aide une case à cocher dans le formulaire de création de compte.
- Séparer les sessions d'administrateurs et d'utilisateurs "normaux"
- Mise en place des politiques de sécurité (CSP)
- Refondre la documentation et y intégrer les parcours utilisateurs
