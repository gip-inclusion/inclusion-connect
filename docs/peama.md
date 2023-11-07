# Fédération d'indentité avec Pôle emploi Agents

Les utilisateurs d'Inclusion Connect ayant une adresse e-mail en @pole-emploi.fr doivent utiliser
le SSO de Pôle emploi pour créer leur compte et se connecter.

Cette fédération met à disposition des informations supplémentaires fournies par Pôle emploi dans l'_IDToken_ :
- **site_pe**: une chaine de caractère qui contient à la fin, entre parenthèse, le code AURORE de la structure. Le format est garanti toujours identique par PE.
- **structure_pe**: le code SAFIR de l'agence de rattachement de l'agent (c'est un _int_).

Ces données sont donc disponibles à chaque connexion avec Inclusion Connect (même lors de la création de compte) et si elles changent côté Pôle emploi, elles seront aussi modifiées dans l'_IDToken_ à la prochaine connexion.

Attention : il n'y a pas de mécanisme côté Inclusion Connect pour prévenir d'un changement de ces informations. C'est à la plateforme partenaire de faire la vérification.
