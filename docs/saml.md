# Le protocole SAML 2.0

## Introduction

En plus d'OpenID Connect, Inclusion Connect expose un fournisseur d'identité
(_Identity Provider_, IdP) SAML 2.0. Il permet à des fournisseurs de service
(_Service Providers_, SP) qui parlent SAML plutôt qu'OIDC de déléguer
l'authentification de leurs utilisateurs à Inclusion Connect.

Le SP émet une `AuthnRequest`, Inclusion Connect authentifie l'utilisateur (avec
les mêmes garde-fous que le flux OIDC : OTP, mot de passe faible ou temporaire,
etc.), puis renvoie une assertion SAML signée contenant l'identité de
l'utilisateur vers l'_Assertion Consumer Service_ (ACS) du SP.

Caractéristiques de l'implémentation :

- **Bindings entrants** (`AuthnRequest` / `LogoutRequest`) : HTTP-Redirect et
  HTTP-POST.
- **Binding sortant** (assertion) : HTTP-POST uniquement. L'ACS du SP **doit**
  donc être déclaré en HTTP-POST dans ses métadonnées.
- **Assertion** signée par défaut, chiffrée si le SP publie un certificat de
  chiffrement.
- **`AuthnRequest`** signée optionnelle, configurable par SP.
- **Single Logout** local (la session Inclusion Connect de l'utilisateur est
  fermée ; aucune propagation vers les autres SP).


## Configuration de l'IdP

L'IdP se configure par variables d'environnement
(`inclusion_connect/settings/base.py`) :

| Variable | Description | Défaut |
| --- | --- | --- |
| `SAML_IDP_ENTITY_ID` | entityID de l'IdP, publié dans ses métadonnées. | `https://connect.inclusion.beta.gouv.fr/saml/idp` |
| `SAML_IDP_SIGNING_KEY_FILE` | Chemin de la clé privée de signature (PEM). | `saml.key` |
| `SAML_IDP_SIGNING_CERT_FILE` | Chemin du certificat de signature (PEM). | `saml.crt` |
| `SAML_XMLSEC1_BINARY` | Chemin du binaire `xmlsec1`. Requis pour le SSO (signature/chiffrement). | _(vide)_ |

`xmlsec1` doit être installé sur l'hôte ou le conteneur ; sans lui, l'émission
d'assertions échoue. L'endpoint de métadonnées, lui, ne dépend pas de `xmlsec1`.

### Générer le couple clé / certificat

Le certificat de signature est auto-signé et sert uniquement à la signature des
assertions SAML (ce n'est pas un certificat TLS). Pour en générer un valable
10 ans :

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout saml.key -out saml.crt \
    -days 3650 \
    -subj "/CN=connect.inclusion.beta.gouv.fr"
```

Pointez ensuite `SAML_IDP_SIGNING_KEY_FILE` / `SAML_IDP_SIGNING_CERT_FILE` vers
ces fichiers.

### Endpoints de l'IdP

Tous sont montés sous `/saml/` (`inclusion_connect/saml/urls.py`) :

| Endpoint | Rôle |
| --- | --- |
| `GET /saml/metadata` | Métadonnées de l'IdP, à fournir au SP. |
| `GET` / `POST /saml/sso` | Single Sign-On (réception de l'`AuthnRequest`). |
| `GET /saml/sso/continue` | Reprise du SSO après authentification de l'utilisateur. |
| `GET` / `POST /saml/slo` | Single Logout local. |

Pour enregistrer Inclusion Connect chez un SP, communiquez-lui l'URL des
métadonnées (`https://<domaine>/saml/metadata`). Elles contiennent l'entityID,
le certificat de signature et les URLs SSO/SLO.


## Enregistrer un fournisseur de service (SP)

L'enregistrement se fait entièrement depuis l'**admin Django**, via le modèle
`SamlServiceProvider` (« service provider SAML »). Aucun fichier de
configuration à éditer.

Champs du formulaire :

- **nom** — libellé interne, sans impact protocolaire.
- **métadonnées XML** — coller les métadonnées SAML du SP. L'`entityID` et les
  URLs ACS en sont extraits automatiquement. Validation à l'enregistrement :
  - le XML doit décrire **exactement un** `EntityDescriptor` ;
  - il doit contenir un `SPSSODescriptor` avec un `AssertionConsumerService` ;
  - au moins un ACS doit être en binding **HTTP-POST** (seul binding de sortie
    émis par l'IdP) ;
  - l'`entityID` doit être unique parmi les SP déjà enregistrés.
- **mapping d'attributs** — JSON, voir [ci-dessous](#attributs-publiés). Vide =
  jeu d'attributs par défaut.
- **format du NameID** :
  - `persistent` (défaut) — `User.username`, c'est-à-dire l'UUID identique au
    `sub` OIDC ;
  - `emailAddress` — l'adresse e-mail.
- **signer l'assertion** (défaut : activé) — signe l'assertion SAML.
- **exiger des AuthnRequest signées** (défaut : désactivé) — rejette les
  `AuthnRequest` non signées du SP. À n'activer qu'une fois le SP capable de
  signer ses requêtes.

> Le **chiffrement de l'assertion** n'a pas de case à cocher : il s'active
> automatiquement si les métadonnées du SP déclarent un `KeyDescriptor`
> `use="encryption"`.

### Attributs publiés

Par défaut, l'IdP publie l'ensemble suivant, sous leurs noms URI/OID standards
(`inclusion_connect/saml/conf.py`) :

| Clé | Nom émis | Source |
| --- | --- | --- |
| `email` | `urn:oid:0.9.2342.19200300.100.1.3` | e-mail de l'utilisateur |
| `given_name` | `urn:oid:2.5.4.42` | prénom |
| `family_name` | `urn:oid:2.5.4.4` | nom |
| `uid` | `urn:oid:0.9.2342.19200300.100.1.1` | clé primaire de l'utilisateur |
| `siret` | `urn:fr:gouv:saml:attribute:siret` | `settings.SIRET` |
| `siren` | `urn:fr:gouv:saml:attribute:siren` | `settings.SIREN` |

Pour restreindre ou personnaliser ce jeu, renseignez **mapping d'attributs**
avec un objet JSON. Un mapping non vide sélectionne le **sous-ensemble** des
attributs à publier, et peut surcharger, par attribut, le `name` et le
`name_format` émis :

```json
{
  "email": {},
  "given_name": { "name": "firstName", "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" },
  "siret": {}
}
```

- Une clé avec un objet vide `{}` publie l'attribut sous son nom par défaut.
- `name` et `name_format` sont tous deux optionnels ; en leur absence, les
  valeurs par défaut (nom URI/OID, `name_format` URI) s'appliquent.
- Seules les clés du tableau ci-dessus sont acceptées ; une clé inconnue ou une
  structure invalide est refusée à l'enregistrement.


## Déroulé d'une connexion (SSO)

1. Le SP redirige l'utilisateur vers `/saml/sso` avec une `AuthnRequest`.
2. L'IdP lit l'`issuer` de la requête et cherche le `SamlServiceProvider`
   correspondant. Issuer absent → erreur ; SP inconnu → erreur.
3. **Utilisateur non authentifié** : la requête SAML est mise en session et
   l'utilisateur est redirigé vers la mire de connexion. Les garde-fous
   post-login (OTP, mot de passe faible/temporaire) s'appliquent **avant**
   l'émission de toute assertion. Une fois connecté, il revient sur
   `/saml/sso/continue` qui reprend le flux.
4. L'IdP vérifie l'`AuthnRequest` selon la politique de signature du SP, puis
   construit l'assertion (identité + `NameID`), la signe et, le cas échéant, la
   chiffre.
5. L'assertion est postée (auto-submit) vers l'ACS HTTP-POST du SP, avec le
   `RelayState` d'origine.
6. Chaque connexion réussie est tracée dans `UserSamlServiceProviderLink`
   (audit : quel utilisateur s'est connecté à quel SP, et quand), pendant
   OIDC `UserApplicationLink`.

## Déconnexion (SLO)

`/saml/slo` implémente un Single Logout **local** : à réception d'une
`LogoutRequest` valide, Inclusion Connect ferme toutes les sessions de
l'utilisateur ciblé puis renvoie une `LogoutResponse`. Il n'y a **pas** de
propagation de la déconnexion vers les autres SP.

Garde-fou : l'endpoint accepte des requêtes non signées, donc la session n'est
réellement fermée que si le `Subject` de la `LogoutRequest` correspond à
l'utilisateur connecté. Une requête non concordante reçoit tout de même une
`LogoutResponse` valide, mais ne déconnecte personne.
