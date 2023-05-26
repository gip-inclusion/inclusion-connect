from bootstrap4.templatetags.bootstrap4 import bootstrap_field
from django import template


register = template.Library()


def make_password_field(form_field, field_class=None):
    return bootstrap_field(
        form_field,
        addon_after="""
        <button class="btn btn-sm btn-link btn-ico" type="button" data-password="toggle">
            <i class="ri-eye-line"></i>
            <span>Afficher</span>
        </button>
        """,
        addon_after_class=None,
        field_class=field_class,
    )


@register.simple_tag
def password_field(form_field):
    return make_password_field(form_field)


@register.inclusion_tag("includes/new_password.html")
def password_field_with_instructions(form_field):
    return {"password_input": make_password_field(form_field, field_class="password-with-instructions")}
