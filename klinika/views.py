import hashlib
import datetime
import os
import bleach
from django.contrib import messages
from .models import MyUser, Pet, Gender_choices, UserType, UserTypeEnum, Species
from django.shortcuts import render, redirect
from sendgrid import SendGridAPIClient
import bcrypt
from klinika.models import Token
from django.contrib.sites.shortcuts import get_current_site


def main(request):
    if request.session.get('my_user', False):
        return render(request, 'klinika/main.html', {'username': request.session.get('my_user')})

    return render(request, 'klinika/main.html')


def about(request):
    if request.session.get('my_user', False):
        return render(request, 'klinika/about.html', {'username': request.session.get('my_user')})

    return render(request, 'klinika/about.html')


def signin(request):
    if request.method == 'POST':
        username = bleach.clean(request.POST['username'])
        password = bleach.clean(request.POST['password'])

        if MyUser.objects.filter(username=username).exists():
            user = MyUser.objects.get(username=username)

            if bcrypt.checkpw(password.encode(encoding='UTF-8'),
                              user.password.replace('b\'', '').replace('\'', '').encode(encoding='UTF-8')):
                request.session['my_user'] = user.username
                messages.success(request, "Zostałeś zalogowany!")
                return render(request, 'klinika/main.html', {'username': username})

        messages.error(request, "Błędne dane")
        return redirect('VetPet')

    else:
        if request.session.get('my_user', False):
            return render(request, 'klinika/main.html', {'username': request.session.get('my_user')})
    return render(request, 'klinika/signin.html')


def signup(request):
    if request.method == "POST":
        username = bleach.clean(request.POST['username'])
        first_name = bleach.clean(request.POST['first_name'])
        last_name = bleach.clean(request.POST['last_name'])
        email = bleach.clean(request.POST['email'])
        pass1 = bleach.clean(request.POST['pass1'])
        pass2 = bleach.clean(request.POST['pass2'])

        if MyUser.objects.filter(username=username):
            messages.error(request, "Nazwa użytkownika jest już zajęta!")
            return redirect('VetPet')
        if MyUser.objects.filter(email=email):
            messages.error(request, "Podany adres email jest już zajęty!")
            return redirect('VetPet')

        if len(username) > 30:
            messages.error(request, "Podana nazwa uzytkownika jest za dluga!")

        if pass1 != pass2:
            messages.error(request, "Hasła muszą się zgadzać!")

        if not username.isalnum():
            messages.error(request, "Nazwa użytkownika musi się składać z liter oraz cyfr!")
            return redirect('VetPet')

        passwd = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())
        myuser = MyUser.objects.create(username=username,
                                       first_name=first_name,
                                       last_name=last_name,
                                       email=email,
                                       password=passwd)
        myuser.save()

        messages.success(request, "Konto utworzone pomyślnie")

        t = hashlib.md5((username + str(datetime.datetime.now())).encode('utf-8')).hexdigest()
        token = Token.objects.create(token=t, user=myuser)
        token.save()

        domain = get_current_site(request).domain

        activate_url = 'http://' + domain + '/activate/' + token.token

        email_body = 'Witaj ' + myuser.username + \
                     '!<br/>Aktywuj swoje konto za pomocą ' \
                     'poniższego linku<br/> <a href="' + activate_url + '">' \
                                                                        '<button>Kliknij by aktywować</button></a>'

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
                    'value': email_body

                },

            ],

        }
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            sg.send(message)

        except Exception as e:
            print(str(e))

    return render(request, 'klinika/signup.html')


def mypets(request):
    if request.session.get('my_user', False):
        owner = MyUser.objects.get(username=request.session.get('my_user', False))
        pets = Pet.objects.filter(owner=owner).all()

        return render(request, 'klinika/mypets.html', {'username': request.session.get('my_user'), 'pet_list': pets})
    else:
        return render(request, 'klinika/signin.html')


def addpet(request):
    if request.session.get('my_user', False):
        if request.method == 'GET':
            return render(request, 'klinika/addpet.html', {'username': request.session.get('my_user')})
        if request.method == 'POST':
            name = bleach.clean(request.POST['name'])
            date_of_birth = bleach.clean(request.POST['date_of_birth'])
            sex = bleach.clean(request.POST['sex'])
            species = bleach.clean(request.POST['species'])
            additional_information = bleach.clean(request.POST['additional_information'])

            if len(name) > 32:
                messages.error(request, "Imie zwierzecia jest zbyt dlugie!")

            if sex.capitalize() not in str(Gender_choices):
                messages.error(request, "Nieprawidłowa płeć!")

            if not Species.objects.filter(species_name=species):
                species = Species.objects.create(species_name=species, additional_information='')
                species.save()

            newspecies = Species.objects.get(species_name=species)

            owner = MyUser.objects.get(username=request.session.get('my_user', False))
            # todo: Profil użytkownika i możliwość edycji profilu
            # if owner.phone_number is None:
            #     messages.error(request,"Uzupełnij dane kontaktowe w swoim profilu przed dodatniem zwierzęcia!")

            user_type = UserType.objects.create(user=owner,
                                                user_type='PET_OWNER')
            user_type.save()
            pet = Pet.objects.create(name=name,
                                     date_of_birth=date_of_birth,
                                     sex=sex,
                                     species=newspecies,
                                     additional_information=additional_information,
                                     owner=owner)
            pet.save()

            return redirect('mypets')
            # return render(request, 'klinika/mypets.html', {'username': request.session.get('my_user')})
    else:
        return render(request, 'klinika/signin.html')


def signout(request):
    request.session.delete()
    messages.success(request, "Zostałeś wylogowany!")
    return redirect('VetPet')


def VerificationView(request, token):
    if Token.objects.filter(token=token).exists():
        t = Token.objects.get(token=token)
        t.user.is_active = True
        t.user.save()
    else:
        return redirect('signin')

    return redirect('signin')
