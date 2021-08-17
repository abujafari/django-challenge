from django.contrib.auth.models import User
from rest_framework import serializers

from vollyball.models import Match, Stadium, Seat


class StadiumSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stadium
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'id')


class MatchSerializer(serializers.ModelSerializer):
    stadium = StadiumSerializer()

    class Meta:
        model = Match
        fields = '__all__'


class SeatSerializer(serializers.ModelSerializer):
    match = MatchSerializer()
    user = UserSerializer()

    class Meta:
        model = Seat
        fields = '__all__'
