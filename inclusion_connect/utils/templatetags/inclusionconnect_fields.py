from bootstrap4.templatetags.bootstrap4 import bootstrap_field
from django import template


register = template.Library()


@register.simple_tag
def password_field(form_field):
    return bootstrap_field(
        form_field,
        addon_after="""
        <button class="btn btn-sm btn-link btn-ico" type="button" data-password="toggle">
            <i class="ri-eye-line"></i>
            <span>Afficher</span>
        </button>
        """,
        addon_after_class=None,
    )
