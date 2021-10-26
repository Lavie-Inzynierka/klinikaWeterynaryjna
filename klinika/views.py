from django.shortcuts import render
from django.http import HttpResponse


def stronaGlowna(request):
    return render(request, 'klinika/stronaGlowna.html')


def informacje(request):
    return render(request, 'klinika/informacje.html')


def logowanie(request):
    return render(request, 'klinika/logowanie.html')
