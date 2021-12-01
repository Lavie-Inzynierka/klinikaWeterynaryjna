import hashlib
import datetime
import os
from django.contrib import messages
from .models import MyUser
from django.shortcuts import render, redirect
from sendgrid import SendGridAPIClient
import bcrypt
from klinika.models import Token
from django.contrib.sites.shortcuts import get_current_site


def main(request):
    return render(request, 'klinika/main.html')


def about(request):
    return render(request, 'klinika/about.html')


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            username = user.username
            messages.success(request, "Zostałeś zalogowany!")
            return render(request, 'klinika/main.html', {'username': username})
        else:
            messages.error(request, "Błędne dane")
            return redirect('VetPet')

    return render(request, 'klinika/signin.html')


def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if MyUser.objects.filter(username=username):
            messages.error(request, "Nazwa użytkownika jest już zajęta!")
            return redirect('VetPet')
        if MyUser.objects.filter(email=email):
            messages.error(request, "Podany adres email jest już zajęty!")
            return redirect('VetPet')

        if len(username) > 10:
            messages.error(request, "Podana nazwa uzytkownika jest za dluga!")

        if pass1 != pass2:
            messages.error(request, "Hasła muszą się zgadzać!")

        if not username.isalnum():
            messages.error(request, "Nazwa użytkownika musi się składać z liter oraz cyfr!")
            return redirect('VetPet')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Konto utworzone pomyślnie")

        t = hashlib.md5((username + str(datetime.datetime.now())).encode('utf-8')).hexdigest()
        token = Token.objects.create(token=t)
        token.save()

        message = {
            'personalizations': [
                {
                    'to': [
                        {
                            'email': myuser.email
                        }
                    ],
                    'subject': 'Witaj w VetPet!'
                }
            ],
            'from': {
                'email': 'vetpet1502@gmail.com'
            },
            'content': [
                {
                    'type': 'text/html',
                    'value': '<html>Aktywuj swoje konto VetPet!</a> '
                             '<br><p>Za pomocą tego tokena: </p></html>' + '<strong>' + token.token + '</strong>'
                },

            ],

        }
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            sg.send(message)

        except Exception as e:
            print(str(e))

        return redirect('signin')

    return render(request, 'klinika/signup.html')


def signout(request):
    logout(request)
    messages.success(request, "Zostałeś wylogowany!")
    return redirect('VetPet')
