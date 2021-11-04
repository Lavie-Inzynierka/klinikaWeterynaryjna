from django.urls import path
from . import views

urlpatterns = [
    path('', views.stronaGlowna, name="VetPet"),
    path('informacje/', views.informacje, name="info"),
    path('logowanie/', views.logowanie, name="logowanie"),
    path('rejestracja/', views.rejestracja, name="rejestracja"),
]
