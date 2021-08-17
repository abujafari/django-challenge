from django.db import models
from django.contrib.auth.models import User


class Stadium(models.Model):
    name = models.CharField(max_length=121)


class Match(models.Model):
    name = models.CharField(max_length=121)
    stadium = models.ForeignKey(Stadium, on_delete=models.CASCADE)
    start_at = models.DateTimeField()


class Seat(models.Model):
    match = models.ForeignKey(Match, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    location = models.IntegerField()
    reserved_at = models.DateTimeField(null=True)
