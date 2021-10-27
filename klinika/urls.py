from django.urls import path
from . import views



urlpatterns = [
    path('', views.stronaGlowna, name="Vet Pet"),
    path('informacje/', views.informacje, name="o nas"),
    path('logowanie/', views.logowanie, name="zaloguj się"),
    path('rejestracja/', views.rejestracja, name="zarejestruj się"),
]
