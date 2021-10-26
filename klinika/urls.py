from django.urls import path
from . import views

urlpatterns = [
    path('', views.stronaGlowna, name="klinika"),
    path('informacje/', views.informacje, name="informacje"),
    path('logowanie/', views.logowanie, name="logowanie"),
]
