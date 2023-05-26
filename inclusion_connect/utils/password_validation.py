import string

from django.core.exceptions import ValidationError


class CnilCompositionPasswordValidator:
    """
    Validate whether the password is conform to CNIL guidelines.

    CNIL guidelines regarding the use case "Avec restriction d'accès":
    https://www.cnil.fr/fr/mots-de-passe-une-nouvelle-recommandation-pour-maitriser-sa-securite
    """

    SPECIAL_CHARS = string.punctuation

    HELP_MSG = "Le mot de passe doit contenir des majuscules, minuscules, chiffres et des caractères spéciaux."

    def validate(self, password, user=None):
        has_lower = any(char.islower() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special_char = any(char in self.SPECIAL_CHARS for char in password)

        if 12 <= len(password) < 14:
            # Exemple 1 : les mots de passe doivent être composés d'au minimum 12 caractères
            # comprenant des majuscules, des minuscules, des chiffres et des caractères spéciaux
            # à choisir dans une liste d'au moins 37 caractères spéciaux possibles.
            if not all([has_lower, has_upper, has_digit, has_special_char]):
                raise ValidationError(self.HELP_MSG, code="cnil_composition")
        elif len(password) >= 14:
            # Booleans are a subtype of integers.
            # https://docs.python.org/3/library/stdtypes.html#numeric-types-int-float-complex
            if (has_lower + has_upper + has_digit + has_special_char) < 3:
                raise ValidationError(self.HELP_MSG, code="cnil_composition")
        else:
            # Should have been taken care of by the MinimumLengthValidator
            raise ValidationError("Le mot de passe ne contient pas assez de caractères.")

    def get_help_text(self):
        return self.HELP_MSG
