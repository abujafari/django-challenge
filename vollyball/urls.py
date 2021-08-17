from django.urls import path

from . import views

urlpatterns = [
    path('login/', views.login),
    path('register/', views.register),
    path('stadiums/', views.stadiums, name='index'),
    path('stadiums/<int:pk>/', views.stadium, name='index'),
    path('matches/', views.matches, name='index'),
    path('matches/<int:pk>/seats', views.match_seats, name='index'),
    path('matches/<int:pk>/seats/<int:seat_id>/book', views.bookSeat.as_view(), name='index'),
]
