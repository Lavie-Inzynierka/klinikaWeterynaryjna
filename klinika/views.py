import os

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


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
        # username = request.POST.get('username')
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username):
            messages.error(request, "Nazwa użytkownika jest już zajęta!")
            return redirect('VetPet')
        if User.objects.filter(email=email):
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

        # todo: Email confirmation with sendgrid and flag setting as active (user)

        message = Mail(
            from_email='vetpet1502@gmail.com',
            to_emails=myuser.email,
            subject='Witaj w VetPet!',
            html_content='<strong>and easy to do anywhere, even with Python</strong>')
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print(response.status_code)
            # print(response.body)
            # print(response.headers)
        except Exception as e:
            print(str(e))
        return redirect('signin')

    return render(request, 'klinika/signup.html')


def signout(request):
    logout(request)
    messages.success(request, "Zostałeś wylogowany!")
    return redirect('VetPet')
