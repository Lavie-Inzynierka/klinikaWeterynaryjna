from django import template

register = template.Library()


@register.filter
def myany(value, name):
    return any(x.user_type == name for x in value)
