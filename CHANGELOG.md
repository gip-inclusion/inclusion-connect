# Journal des modifications


## [Non publié]

### Ajouté

- Fournisseur d'identité SAML 2.0 : endpoint de métadonnées IdP dynamique (`GET /saml/metadata`).
- Fournisseur d'identité SAML 2.0 : SSO initié par le SP (`/saml/sso`, bindings HTTP-Redirect et HTTP-POST en entrée) émettant une assertion signée auto-postée vers l'ACS, après passage par la connexion et la double authentification obligatoires.
- Enregistrement des SP SAML dans l'admin Django à partir de leurs métadonnées XML (entityID et ACS extraits automatiquement, sans déploiement).
- Politique de release d'attributs par SP : sous-ensemble publié et, par attribut, nom et NameFormat émis (`email`, `given_name`, `family_name`, `usual_name`, `uid`, `siret`, `siren`) ; format du NameID configurable (`persistent` par défaut, identique au `sub` OIDC, ou `emailAddress`).
- Chiffrement de l'assertion par SP, déclenché lorsque les métadonnées du SP publient un certificat de chiffrement.
- Réglages `SAML_IDP_ENTITY_ID`, `SAML_IDP_SIGNING_KEY_FILE` et `SAML_IDP_SIGNING_CERT_FILE` (certificat de signature dédié, cycle de vie indépendant de `oidc.pem`).
- Réglage `SAML_XMLSEC1_BINARY` (chemin du binaire `xmlsec1`, sinon détection automatique sur le `PATH`).
- Fournisseur d'identité SAML 2.0 : vérification de la signature des AuthnRequest (signature de la query string en binding HTTP-Redirect, signature XML enveloppée en HTTP-POST) ; option par SP `require_signed_authn_request` pour rendre la signature obligatoire.
- Fournisseur d'identité SAML 2.0 : déconnexion locale (Single Logout) initiée par le SP (`/saml/slo`, bindings HTTP-Redirect et HTTP-POST) terminant la session IC et renvoyant un `LogoutResponse` ; endpoint SLS annoncé dans les métadonnées.
- Suivi des SP SAML utilisés par chaque utilisateur (lien `UserSamlServiceProviderLink`, affiché dans l'admin) et journalisation structurée des événements SAML, alignée sur l'OIDC.
- Page d'erreur générique pour les requêtes SAML invalides ou émanant d'un SP non reconnu (aucune information renvoyée à un ACS non validé).

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
