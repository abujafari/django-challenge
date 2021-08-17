import datetime
import json

from django.core import serializers
from django.http import HttpResponse, JsonResponse, Http404
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.views import generic
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from . import validators
from .serializers import MatchSerializer, SeatSerializer
from .validators import validate_or_400
from .helper import rest_response
from .models import Stadium, Match, Seat


def register(request):
    validate_or_400(validators.Register, request.POST)

    user = User.objects.create_user(request.POST['username'], request.POST['email'], request.POST['password'])
    user.save()

    user = User.objects.get(username=request.POST['username'])
    refresh = RefreshToken.for_user(user)

    return rest_response({
        'username': user.username,
        'email': user.email,
        'id': user.id,
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    })


def login(request):
    if request.method == "POST":
        validate_or_400(validators.Login, request.POST)

        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return rest_response({
                'username': user.username,
                'email': user.email,
                'id': user.id,
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            })
        else:
            return rest_response([], ok=False, message='username or password is invalid', status=401)
    else:
        raise Http404("Page not Found")


def stadiums(req):
    if req.method == 'GET':
        stadiums = Stadium.objects.all().values()
        return rest_response(stadiums)
    elif req.method == 'POST':
        validate_or_400(validators.CreateStadium, req.POST)
        data = Stadium.objects.create(name=req.POST['name'])
        data.save()
        return rest_response(data, message='stadium created')


def stadium(req, pk):
    stadium = get_object_or_404(Stadium, pk=pk)
    return rest_response(stadium)


def matches(req):
    # retrieve matches
    if req.method == 'GET':
        matches = Match.objects.all();
        return rest_response(MatchSerializer(matches, many=True).data)
    # create match
    elif req.method == 'POST':
        validate_or_400(validators.CreateMatch, req.POST)

        match = Match.objects.create(
            name=req.POST['name'],
            start_at=req.POST['start_at'],
            stadium_id=req.POST['stadium_id']
        )
        match.save()
        return rest_response(MatchSerializer(match).data, message='match created successfully')


def match_seats(req, pk):
    if req.method == 'GET':
        seats = Seat.objects.all().filter(match_id=pk)
        return rest_response(SeatSerializer(seats, many=True).data)

    elif req.method == 'POST':
        seat = Seat.objects.create(location=req.POST['location'], match_id=pk)
        seat.save()

        return rest_response(SeatSerializer(seat).data)


class bookSeat(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, pk, seat_id):
        seat = get_object_or_404(Seat, match_id=pk, id=seat_id, user_id=None);
        seat.user_id = request.user.id
        seat.reserved_at = datetime.datetime.now()
        seat.save()
        return rest_response(SeatSerializer(seat).data, message='booked successfully')
