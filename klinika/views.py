from django.shortcuts import render
from django.http import HttpResponse


def stronaGlowna(request):
    return render(request, 'klinika/dom.html')


def informacje(request):
    return render(request, 'klinika/informacje.html')


def logowanie(request):
    return render(request, 'klinika/logowanie.html')


def rejestracja(request):
    return render(request, 'klinika/rejestracja.html')