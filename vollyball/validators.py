from django import forms
from django.core.exceptions import BadRequest


def validate_or_400(validator, form):
    if not validator(form).is_valid():
        raise BadRequest
    else:
        return True


class Login(forms.Form):
    email = forms.EmailField()
    password = forms.CharField()


class Register(forms.Form):
    email = forms.EmailField()
    username = forms.CharField()
    password = forms.CharField()


class CreateStadium(forms.Form):
    name = forms.CharField(required=True)


class CreateMatch(forms.Form):
    name = forms.CharField()
    stadium_id = forms.IntegerField()
    start_at = forms.DateTimeField()
