import json
from django.core.serializers.json import DjangoJSONEncoder

from django.core import serializers
from django.db.models import Model
from django.http import HttpResponse, JsonResponse
from django.db.models.query import QuerySet


def rest_response(data, ok=True, message='', status=200):
    if isinstance(data, QuerySet):
        data = list(data)

    if isinstance(data, Model):
        data = serializers.serialize('json', [data])
        data = json.loads(data)
        data = data[0].get('fields')

    return HttpResponse(
        json.dumps({
            'ok': ok,
            'message': message,
            'data': data
        }, cls=DjangoJSONEncoder),
        status=status,
        content_type="application/json"
    )
