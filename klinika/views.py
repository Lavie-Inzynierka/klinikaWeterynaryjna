import hashlib
import datetime
import os
import string
import bleach
from django.contrib import messages
from django.db.models import Min
from django.http import HttpResponse
from .models import *
from django.shortcuts import render, redirect
from sendgrid import SendGridAPIClient
import bcrypt
from klinika.models import Token
from django.contrib.sites.shortcuts import get_current_site
import re
import json
from .json_validator import addpresc_validator
from .mytools import randstr


# region main
def main(request):
    if request.session.get('my_user', False):
        return render(request, 'klinika/main.html', {'username': request.session.get('my_user'),
                                                     'adm': request.session.get('is_adm'),
                                                     'vet': request.session.get('is_vet'),
                                                     'rec': request.session.get('is_rec'),
                                                     'own': request.session.get('is_own'),
                                                     })

    return render(request, 'klinika/main.html')


# endregion

# region about
def about(request):
    if request.session.get('my_user', False):
        return render(request, 'klinika/about.html', {'username': request.session.get('my_user'),
                                                      'title': 'O aplikacji',
                                                      'adm': request.session.get('is_adm'),
                                                      'vet': request.session.get('is_vet'),
                                                      'rec': request.session.get('is_rec'),
                                                      'own': request.session.get('is_own'),
                                                      })

    return render(request, 'klinika/about.html')


# endregion

# region users

# region signin
def signin(request):
    if request.method == 'POST':
        username = bleach.clean(request.POST['username'])
        password = bleach.clean(request.POST['password'])

        if MyUser.objects.filter(username=username).exists():
            user = MyUser.objects.get(username=username)

            if not user.is_active:
                return render(request, 'klinika/signin.html', {'error': 'Nieprawidłowy login lub hasło!'})

            if bcrypt.checkpw(password.encode(encoding='UTF-8'),
                              user.password.replace('b\'', '').replace('\'', '').encode(encoding='UTF-8')):
                request.session['my_user'] = user.username

                request.session['is_adm'] = UserType.objects.filter(user__id=user.id, user_type='ADMIN').exists()
                request.session['is_vet'] = UserType.objects.filter(user__id=user.id, user_type='VET').exists()
                request.session['is_rec'] = UserType.objects.filter(user__id=user.id, user_type='RECEPTIONIST').exists()
                request.session['is_own'] = UserType.objects.filter(user__id=user.id, user_type='PET_OWNER').exists()

                return redirect('VetPet')

        return render(request, 'klinika/signin.html', {'error': 'Nieprawidłowy login lub hasło!'})

    else:
        if request.session.get('my_user', False):
            return redirect('VetPet')
    return render(request, 'klinika/signin.html', {'title': 'Logowanie'})


# endregion

# region signup

def signup(request):
    if MyUser.objects.filter().exists():
        if request.method == "POST":
            username = bleach.clean(request.POST['username'])
            first_name = bleach.clean(request.POST['first_name'])
            last_name = bleach.clean(request.POST['last_name'])
            email = bleach.clean(request.POST['email'])
            pass1 = bleach.clean(request.POST['pass1'])
            pass2 = bleach.clean(request.POST['pass2'])

            if MyUser.objects.filter(username=username).exists():
                return render(request, 'klinika/signup.html', {'error1': "Nazwa użytkownika jest już zajęta!",
                                                               'title': 'Rejestracja'})
            if MyUser.objects.filter(email=email).exists():
                return render(request, 'klinika/signup.html', {'error2': "Podany adres email jest już zajęty!",
                                                               'title': 'Rejestracja'})

            if len(username) > 30:
                return render(request, 'klinika/signup.html', {'error3': "Podana nazwa uzytkownika jest za dluga!",
                                                               'title': 'Rejestracja'})

            if pass1 != pass2:
                messages.error(request, "Hasła muszą się zgadzać!")
                return render(request, 'klinika/signup.html', {'error4': "Hasła muszą się zgadzać!",
                                                               'title': 'Rejestracja'})

            if not username.isalnum():
                return render(request, 'klinika/signup.html',
                              {'error4': "Nazwa użytkownika musi się składać z liter oraz cyfr!",
                               'title': 'Rejestracja'})

            regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

            if not re.search(regex, email):
                return render(request, 'klinika/signup.html', {'error6': "Nieprawidłowy adress email!",
                                                               'title': 'Rejestracja'})

            passwd = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())
            myuser = MyUser.objects.create(username=username,
                                           first_name=first_name,
                                           last_name=last_name,
                                           email=email,
                                           password=passwd)
            myuser.save()

            t = hashlib.md5((username + str(datetime.now())).encode('utf-8')).hexdigest()
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

            return render(request, 'klinika/signup.html', {'success': "Konto utworzone pomyślnie!",
                                                           'title': 'Rejestracja'})

        return render(request, 'klinika/signup.html', {'title': 'Rejestracja'})

    return render(request, 'klinika/signup.html', {'system_error': "Skonfiguruj aplikacje!",
                                                   'title': 'Rejestracja'
                                                   })


# endregion

# region signout
def signout(request):
    request.session.delete()
    messages.success(request, "Zostałeś wylogowany!")
    return redirect('VetPet')


# endregion

# region verification

def VerificationView(request, token):
    if Token.objects.filter(token=token).exists():
        t = Token.objects.get(token=token)
        if t.expires_at > datetime.now():
            t.user.is_active = True
            t.user.save()
    else:
        return redirect('signin')

    return redirect('signin')


# endregion

# region profile

def profile(request):
    if request.session.get('my_user', False):

        user = MyUser.objects.get(username=request.session.get('my_user'))
        if request.method == "POST":
            if request.POST['type'] == 'first_name':
                fname = bleach.clean(request.POST['first_name'])

                if Owner.objects.filter(user=user).exists():
                    owner = Owner.objects.get(user=user)
                    owner.first_name = fname
                    owner.save()

                user.first_name = fname
                user.save()

            if request.POST['type'] == 'last_name':
                lname = bleach.clean(request.POST['last_name'])

                if Owner.objects.filter(user=user).exists():
                    owner = Owner.objects.get(user=user)
                    owner.last_name = lname
                    owner.save()

                user.last_name = lname
                user.save()

            if request.POST['type'] == 'password':
                passwd = bleach.clean(request.POST['pass'])
                pass1 = bleach.clean(request.POST['pass1'])
                pass2 = bleach.clean(request.POST['pass2'])

                if not bcrypt.checkpw(passwd.encode(encoding='UTF-8'),
                                      user.password.replace('b\'', '').replace('\'', '').encode(
                                          encoding='UTF-8')) or pass1 != pass2:
                    try:
                        user_adress = UserAddresses.objects.get(user=user, current=True) or None

                    except:
                        return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                        'usr': user,
                                                                        'adr': 'Brak adresu zamieszkania',
                                                                        'error': 'Nieprawidłowe hasło/a!',
                                                                        'title': 'Mój profil',
                                                                        'adm': request.session.get('is_adm'),
                                                                        'vet': request.session.get('is_vet'),
                                                                        'rec': request.session.get('is_rec'),
                                                                        'own': request.session.get('is_own'),
                                                                        })

                    return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                    'usr': user,
                                                                    'adr': user_adress.address,
                                                                    'error': 'Nieprawidłowe hasło/a!',
                                                                    'title': 'Mój profil',
                                                                    'adm': request.session.get('is_adm'),
                                                                    'vet': request.session.get('is_vet'),
                                                                    'rec': request.session.get('is_rec'),
                                                                    'own': request.session.get('is_own'),
                                                                    })

                password = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())
                user.password = password
                user.save()

            if request.POST['type'] == 'phone_number':
                phone = bleach.clean(request.POST['phone_number'])

                if Owner.objects.filter(user=user).exists():
                    owner = Owner.objects.get(user=user)
                    owner.phone_number = phone
                    owner.save()
                user.phone_number = phone
                user.save()

            if request.POST['type'] == 'email':
                email = bleach.clean(request.POST['email'])
                regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

                if not re.search(regex, email) or MyUser.objects.filter(email=email).exists():
                    try:
                        user_adress = UserAddresses.objects.get(user=user, current=True) or None
                    except:
                        return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                        'usr': user,
                                                                        'adr': 'Brak adresu zamieszkania',
                                                                        'error': 'Nieprawidłowy adres email!',
                                                                        'title': 'Mój profil',
                                                                        'adm': request.session.get('is_adm'),
                                                                        'vet': request.session.get('is_vet'),
                                                                        'rec': request.session.get('is_rec'),
                                                                        'own': request.session.get('is_own'),
                                                                        })

                    return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                    'usr': user,
                                                                    'adr': user_adress.address,
                                                                    'error': 'Nieprawidłowy adres email!',
                                                                    'title': 'Mój profil',
                                                                    'adm': request.session.get('is_adm'),
                                                                    'vet': request.session.get('is_vet'),
                                                                    'rec': request.session.get('is_rec'),
                                                                    'own': request.session.get('is_own'),
                                                                    })
                if Owner.objects.filter(user=user).exists():
                    owner = Owner.objects.get(user=user)
                    owner.email = email
                    owner.save()

                user.email = email
                user.save()

            if request.POST['type'] == 'address':

                if UserAddresses.objects.filter(user=user).exists():
                    user_adress = UserAddresses.objects.get(user=user, current=True) or None
                    user_adress.current = False
                    user_adress.save()
                address = bleach.clean(request.POST['address'])
                uadress = UserAddresses.objects.create(
                    address=address,
                    user=user,
                    current=True
                )
                uadress.save()

        try:
            user_adress = UserAddresses.objects.get(user=user, current=True) or None

        except:
            return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                            'usr': user,
                                                            'adr': 'Brak adresu zamieszkania',
                                                            'title': 'Mój profil',
                                                            'adm': request.session.get('is_adm'),
                                                            'vet': request.session.get('is_vet'),
                                                            'rec': request.session.get('is_rec'),
                                                            'own': request.session.get('is_own'),
                                                            })

        return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                        'usr': user,
                                                        'title': 'Mój profil',
                                                        'adr': user_adress.address,
                                                        'adm': request.session.get('is_adm'),
                                                        'vet': request.session.get('is_vet'),
                                                        'rec': request.session.get('is_rec'),
                                                        'own': request.session.get('is_own'),
                                                        })
    else:
        return redirect('signin')


def profiledeactivation(request, uid):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(id=uid)
        user.is_active = False
        user.save()
        request.session.delete()
        return redirect('signin')


# endregion
# endregion

# region pets

def pets(request):
    if request.session.get('my_user', False):
        allpets = Pet.objects.filter().all()
        if allpets.count() == 0:
            return render(request, 'klinika/pets.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'pet_list': 'Brak zwierząt do wyświetlenia',
                           'title': 'Zwierzęta',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pets.html',
                      {'username': request.session.get('my_user'),
                       'pet_list': allpets,
                       'title': 'Zwierzęta',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def pet(request, petid):
    if request.session.get('my_user', False):

        try:
            pet = Pet.objects.get(id=petid)
            if Visit.objects.filter(pet__id=petid, status='Zaplanowana').exists():
                recdate = Visit.objects.filter(pet__id=petid,
                                               status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])
                nothing = False
            else:
                nothing = True
                visit = 'Brak wizyt do wyświetlenia!'
            if Prescription.objects.filter(pet__id=petid, status='Wystawiona').exists():
                recexpdate = Prescription.objects.filter(pet__id=petid,
                                                         status='Wystawiona').aggregate(
                    expiration_date=Min('expiration_date'))
                prescription = Prescription.objects.get(pet__id=petid, status='Wystawiona',
                                                        expiration_date=recexpdate['expiration_date'])

                cures = PrescriptionCure.objects.filter(prescription__id=prescription.id).all()

                nothing2 = False
            else:
                nothing2 = True
                prescription = 'Brak recept do wyświetlenia!'
                cures = 'Brak leków do wyświetlenia!'

            if request.method == "POST":
                if request.POST['type'] == 'additional_information':
                    additional_information = bleach.clean(request.POST['additional_information'])
                    pet.additional_information = additional_information
                    pet.save()

        except:
            return render(request, 'klinika/pet.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono zwierzęcia',
                           'title': 'Podgląd zwierzęcia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pet.html', {'username': request.session.get('my_user'),
                                                    'pet': pet,
                                                    'visit': visit,
                                                    'presc': prescription,
                                                    'cures': cures,
                                                    'nothing': nothing,
                                                    'nothing2': nothing2,
                                                    'title': 'Podgląd zwierzęcia',
                                                    'adm': request.session.get('is_adm'),
                                                    'vet': request.session.get('is_vet'),
                                                    'rec': request.session.get('is_rec'),
                                                    'own': request.session.get('is_own'),
                                                    })
    else:
        return redirect('signin')


def addpets(request):
    if request.session.get('my_user', False):
        owners = Owner.objects.filter().all()
        if request.method == 'GET':
            return render(request, 'klinika/addpets.html', {'username': request.session.get('my_user'),
                                                            'owners': owners,
                                                            'title': 'Dodawanie zwierzęcia',
                                                            'adm': request.session.get('is_adm'),
                                                            'vet': request.session.get('is_vet'),
                                                            'rec': request.session.get('is_rec'),
                                                            'own': request.session.get('is_own'),
                                                            })
        if request.method == 'POST':
            name = bleach.clean(request.POST['name'])
            date_of_birth = bleach.clean(request.POST['date_of_birth'])
            sex = bleach.clean(request.POST['sex'])
            species_name = bleach.clean(request.POST['species'])
            additional_information = bleach.clean(request.POST['additional_information'])

            if len(name) > 32:
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Imię zwierzęcia jest zbyt długie',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if sex.capitalize() not in str(Gender_choices):
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa płeć!',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if not Species.objects.filter(species_name=species_name):
                species = Species.objects.create(species_name=species_name, additional_information='')
                species.save()

            if datetime.strptime(date_of_birth, '%Y-%m-%d') > datetime.now():
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa data urodzenia!',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            newspecies = Species.objects.get(species_name=species_name)

            if request.POST['own'] == 'Dodaj':
                first_name = bleach.clean(request.POST['first_name'])
                last_name = bleach.clean(request.POST['last_name'])
                phone_number = bleach.clean(request.POST['phone_number'])
                email = bleach.clean(request.POST['email'])

                owner = Owner.objects.create(
                    first_name=first_name,
                    last_name=last_name,
                    phone_number=phone_number,
                    email=email)

                owner.save()
            else:
                if not Owner.objects.filter(email=request.POST['own']).exists():
                    user = MyUser.objects.get(email=request.POST['own'])
                    owner = Owner.objects.create(
                        first_name=user.first_name,
                        last_name=user.last_name,
                        phone_number=user.phone_number,
                        email=user.email,
                        user=user
                    )
                    owner.save()
                else:
                    owner = Owner.objects.get(email=request.POST['own'])


            pet = Pet.objects.create(name=name,
                                     date_of_birth=date_of_birth,
                                     sex=sex,
                                     species=newspecies,
                                     additional_information=additional_information,
                                     owner=owner)

            pet.save()

            return redirect('pets')
    else:
        return redirect('signin')


# region User pets
def mypets(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        try:
            owner = Owner.objects.get(user=user) or None
            pets = Pet.objects.filter(owner=owner).all() or None
        except:
            return render(request, 'klinika/pets.html',
                          {'username': request.session.get('my_user'),
                           'pet_list': 'Brak zwierząt do wyświetlenia',
                           'empty': True,
                           'userpets': True,
                           'title': 'Moje zwierzęta',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pets.html',
                      {'username': request.session.get('my_user'),
                       'userpets': True,
                       'pet_list': pets,
                       'title': 'Moje zwierzęta',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def mypet(request, petid):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        owner = Owner.objects.get(user=user)

        try:
            pet = Pet.objects.get(id=petid, owner=owner)

            if Visit.objects.filter(pet__id=petid, status='Zaplanowana').exists():
                recdate = Visit.objects.filter(pet__id=petid,
                                               status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])
                nothing = False
            else:
                nothing = True
                visit = 'Brak wizyt do wyświetlenia!'

            if Prescription.objects.filter(pet__id=petid, status='Wystawiona').exists():
                recexpdate = Prescription.objects.filter(pet__id=petid,
                                                         status='Wystawiona').aggregate(
                    expiration_date=Min('expiration_date'))
                prescription = Prescription.objects.get(pet__id=petid, status='Wystawiona',
                                                        expiration_date=recexpdate['expiration_date'])

                cures = PrescriptionCure.objects.filter(prescription__id=prescription.id).all()

                nothing2 = False
            else:
                nothing2 = True
                prescription = 'Brak recept do wyświetlenia!'
                cures = 'Brak leków do wyświetlenia!'

            if request.method == "POST":

                if request.POST['type'] == 'name':
                    name = bleach.clean(request.POST['name'])
                    if len(name) > 32:
                        return render(request, 'klinika/pet.html',
                                      {'username': request.session.get('my_user'),
                                       'error': 'Imię zwierzęcia jest zbyt długie',
                                       'pet': pet,
                                       'title': 'Moje zwierzę',
                                       'visit': visit,
                                       'userpets': True,
                                       'nothing': nothing,
                                       'nothing2': nothing2,
                                       'presc': prescription,
                                       'cures': cures,
                                       'adm': request.session.get('is_adm'),
                                       'vet': request.session.get('is_vet'),
                                       'rec': request.session.get('is_rec'),
                                       'own': request.session.get('is_own'),
                                       })
                    pet.name = name
                    pet.save()

                if request.POST['type'] == 'additional_information':
                    additional_information = bleach.clean(request.POST['additional_information'])
                    pet.additional_information = additional_information
                    pet.save()
        except:
            return render(request, 'klinika/pet.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono zwierzęcia',
                           'title': 'Moje zwierzę',
                           'userpets': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pet.html', {'username': request.session.get('my_user'),
                                                    'pet': pet,
                                                    'title': 'Moje zwierzę',
                                                    'visit': visit,
                                                    'userpets': True,
                                                    'nothing': nothing,
                                                    'nothing2': nothing2,
                                                    'presc': prescription,
                                                    'cures': cures,
                                                    'adm': request.session.get('is_adm'),
                                                    'vet': request.session.get('is_vet'),
                                                    'rec': request.session.get('is_rec'),
                                                    'own': request.session.get('is_own'),
                                                    })
    else:
        return redirect('signin')


def addpet(request):
    if request.session.get('my_user', False):
        if request.method == 'GET':
            return render(request, 'klinika/addpet.html', {'username': request.session.get('my_user'),
                                                           'title': 'Dodawanie zwierzęcia',
                                                           'adm': request.session.get('is_adm'),
                                                           'vet': request.session.get('is_vet'),
                                                           'rec': request.session.get('is_rec'),
                                                           'own': request.session.get('is_own'),
                                                           })
        if request.method == 'POST':
            name = bleach.clean(request.POST['name'])
            date_of_birth = bleach.clean(request.POST['date_of_birth'])
            sex = bleach.clean(request.POST['sex'])
            species = bleach.clean(request.POST['species'])
            additional_information = bleach.clean(request.POST['additional_information'])

            if len(name) > 32:
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Imię zwierzęcia jest zbyt długie',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if sex.capitalize() not in str(Gender_choices):
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa płeć!',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if not Species.objects.filter(species_name=species):
                species = Species.objects.create(species_name=species, additional_information='')
                species.save()

            if datetime.strptime(date_of_birth, '%Y-%m-%d') > datetime.now():
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa data urodzenia!',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            newspecies = Species.objects.get(species_name=species)

            user = MyUser.objects.get(username=request.session.get('my_user', False))
            if not user.phone_number:
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Uzupełnij dane kontaktowe w swoim profilu przed dodatniem zwierzęcia!',
                               'title': 'Dodawanie zwierzęcia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            if not Owner.objects.filter(user=user).exists():
                owner = Owner.objects.create(
                    first_name=user.first_name,
                    last_name=user.last_name,
                    phone_number=user.phone_number,
                    email=user.email,
                    user=user)

                owner.save()
            owner = Owner.objects.get(user=user)
            if not UserType.objects.filter(user=user, user_type='PET_OWNER').exists():
                user_type = UserType.objects.create(user=user,
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
    else:
        return redirect('signin')


# endregion
# endregion

# region visits
def allvisits(request):
    if request.session.get('my_user', False):
        allvisit = Visit.objects.filter().all()
        if allvisit.count() == 0:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'title': 'Wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'visit_list': allvisit,
                       'title': 'Wizyty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def myvisits(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        if Owner.objects.filter(user=user).exists():
            owner = Owner.objects.get(user=user)
            allvisit = Visit.objects.filter(pet__owner__user_id=owner.user.id)
        else:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'hide': True,
                           'title': 'Moje wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        if allvisit.count() == 0:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'hide': True,
                           'title': 'Moje wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'hide': True,
                       'title': 'Moje wizyty',
                       'visit_list': allvisit,
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def upcomvisits(request):
    if request.session.get('my_user', False):
        allvisit = Visit.objects.filter(status='Zaplanowana').all()
        if allvisit.count() == 0:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'title': 'Zaplanowane wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'visit_list': allvisit,
                       'title': 'Zaplanowane wizyty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


# odbyte wizyry
def visits(request):
    if request.session.get('my_user', False):
        allvisit = Visit.objects.filter(status='Odbyta').all()
        if allvisit.count() == 0:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'hide': True,
                           'title': 'Odbyte wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'hide': True,
                       'visit_list': allvisit,
                       'title': 'Odbyte wizyty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def canceledvisits(request):
    if request.session.get('my_user', False):
        allvisit = Visit.objects.filter(status='Anulowana').all()
        if allvisit.count() == 0:
            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'hide': True,
                           'empty': True,
                           'title': 'Anulowane wizyty',
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'hide': True,
                       'visit_list': allvisit,
                       'title': 'Anulowane wizyty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def addvisit(request):
    if request.session.get('my_user', False):
        pets = Pet.objects.filter().all()
        vets = UserType.objects.filter(user_type='VET').all()
        owners = UserType.objects.filter(user_type='PET_OWNER').all()
        if request.method == 'GET':
            return render(request, 'klinika/addvisit.html',
                          {'username': request.session.get('my_user'),
                           'pets': pets,
                           'title': 'Dodawanie wizyty',
                           'vets': vets,
                           'owners': owners,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        if request.method == 'POST':
            visit_date = bleach.clean(request.POST['visit_date'])
            visit_time = bleach.clean(request.POST['visit_time'])
            note = bleach.clean(request.POST['note'])

            now = datetime.now()
            if datetime.strptime(visit_date + 'T' + visit_time, '%Y-%m-%dT%H:%M') < now:
                return render(request, 'klinika/addvisit.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowy czas wizyty!',
                               'pets': pets,
                               'title': 'Dodawanie wizyty',
                               'vets': vets,
                               'owners': owners,
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if request.POST['pet'] == 'Dodaj':
                if request.POST['own'] == 'Dodaj':
                    first_name = bleach.clean(request.POST['first_name'])
                    last_name = bleach.clean(request.POST['last_name'])
                    phone_number = bleach.clean(request.POST['phone_number'])
                    email = bleach.clean(request.POST['email'])

                    owner = Owner.objects.create(
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number,
                        email=email)
                    owner.save()
                else:
                    user = MyUser.objects.get(email=request.POST['own'])
                    if not Owner.objects.filter(user=user).exists():
                        owner = Owner.objects.create(
                            first_name=user.first_name,
                            last_name=user.last_name,
                            phone_number=user.phone_number,
                            email=user.email,
                            user=user
                        )
                        owner.save()
                    owner = Owner.objects.get(user=user)

                name = bleach.clean(request.POST['name'])
                date_of_birth = bleach.clean(request.POST['date_of_birth'])
                sex = bleach.clean(request.POST['sex'])
                species = bleach.clean(request.POST['species'])
                additional_information = bleach.clean(request.POST['additional_information'])
                if not Species.objects.filter(species_name=species).exists():
                    species = Species.objects.create(species_name=species, additional_information='')
                    species.save()
                newspecies = Species.objects.get(species_name=species)

                pet = Pet.objects.create(name=name,
                                         date_of_birth=date_of_birth,
                                         sex=sex,
                                         species=newspecies,
                                         additional_information=additional_information,
                                         owner=owner)
                pet.save()
            else:
                pet = Pet.objects.get(id=request.POST['pet'])
            vet = MyUser.objects.get(email=request.POST['vet'])
            visit = Visit.objects.create(visit_date=visit_date,
                                         visit_time=visit_time,
                                         visit_planned=datetime.now(),
                                         status='Zaplanowana',
                                         pet=pet,
                                         vet=vet,
                                         note=note)
            visit.save()
            return redirect('allvisits')
    else:
        return redirect('signin')


def visit(request, visitid):
    if request.session.get('my_user', False):
        try:
            visit = Visit.objects.get(id=visitid)
            status = visit.status

            if status == 'Odbyta':
                if Prescription.objects.filter(pet__id=visit.pet.id, status='Wystawiona').exists():
                    recexpdate = Prescription.objects.filter(pet_id=visit.pet.id,
                                                             status='Wystawiona').aggregate(
                        expiration_date=Min('expiration_date'))
                    prescription = Prescription.objects.get(pet__id=visit.pet.id, status='Wystawiona',
                                                            expiration_date=recexpdate['expiration_date'])

                    cures = PrescriptionCure.objects.filter(prescription__id=prescription.id).all()

                    nothing = False
                else:
                    nothing = True
                    prescription = 'Brak recept do wyświetlenia!'
                    cures = 'Brak leków do wyświetlenia!'

                if Treatment.objects.filter(pet__id=visit.pet.id).exists():
                    recdttreat = Treatment.objects.filter(pet__id=visit.pet.id).aggregate(
                        date_time_treatment=Min('date_time_treatment'))
                    treatment = Treatment.objects.get(pet__id=visit.pet.id,
                                                      date_time_treatment=recdttreat['date_time_treatment'])
                    nothing2 = False
                else:
                    nothing2 = True
                    treatment = 'Brak historii leczenia do wyświetlenia!'
            else:
                nothing = True
                prescription = 'Brak recept do wyświetlenia!'
                cures = 'Brak leków do wyświetlenia!'
                nothing2 = True
                treatment = 'Brak historii leczenia do wyświetlenia!'

            if request.method == 'POST':
                if request.POST['type'] == 'visit_date':
                    visit_date = bleach.clean(request.POST['visit_date'])
                    visit.visit_date = visit_date
                    visit.save()

                if request.POST['type'] == 'visit_time':
                    visit_time = bleach.clean(request.POST['visit_time'])
                    visit.visit_time = visit_time
                    visit.save()

                visit = Visit.objects.get(id=visitid)

            return render(request, 'klinika/the-visit.html',
                          {'username': request.session.get('my_user'),
                           'visit': visit,
                           'title': 'Podgląd wizyty',
                           'pastvisit': status,
                           'nothing': nothing,
                           'nothing2': nothing2,
                           'treat': treatment,
                           'presc': prescription,
                           'cures': cures,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except:
            return render(request, 'klinika/the-visit.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak danych wizyty!',
                           'title': 'Podgląd wizyty',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


# endregion

# region prescriptions
def all_prescriptions(request):
    if request.session.get('my_user', False):
        allprescriptions = Prescription.objects.filter().all()
        if allprescriptions.count() == 0:
            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'title': 'Recepty',
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
                       'title': 'Recepty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def myprescriptions(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        if Owner.objects.filter(user=user).exists():
            owner = Owner.objects.get(user=user)
            allprescriptions = Prescription.objects.filter(owner=owner).all()
        else:
            allprescriptions = 0
        if allprescriptions.count() == 0:
            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'title': 'Moje recepty',
                           'hide': True,
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
                       'hide': True,
                       'title': 'Moje recepty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def prescriptions(request):
    if request.session.get('my_user', False):
        allprescriptions = Prescription.objects.filter(status='Wystawiona').all()
        if allprescriptions.count() == 0:
            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'title': 'Wystawione recepty',
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
                       'title': 'Wystawione recepty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def completedprescriptions(request):
    if request.session.get('my_user', False):
        allprescriptions = Prescription.objects.filter(status='Zrealizowana').all()
        if allprescriptions.count() == 0:
            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'hide': True,
                           'title': 'Zrealizowane recepty',
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
                       'hide': True,
                       'title': 'Zrealizowane recepty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def expiredprescriptions(request):
    if request.session.get('my_user', False):
        allprescriptions = Prescription.objects.filter(status='Wygasla').all()
        if allprescriptions.count() == 0:
            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'empty': True,
                           'hide': True,
                           'title': 'Wygasłe recepty',
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
                       'hide': True,
                       'title': 'Wygasłe recepty',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def addprescription(request):
    if request.session.get('my_user', False):
        pets = Pet.objects.filter().all()
        owners = Owner.objects.filter().all()
        cures = Cure.objects.filter().all()
        prescode = randstr.id_generator(22, string.digits)
        while Prescription.objects.filter(code=prescode).exists():
            prescode = randstr.id_generator(22, string.digits)

        if request.method == 'GET':
            return render(request, 'klinika/addprescription.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Dodawanie recepty',
                           'pets': pets,
                           'owners': owners,
                           'cures': cures,
                           'code': prescode,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        if request.method == 'POST':
            vet = MyUser.objects.get(username=request.session.get('my_user'))
            mybody = request.body.decode('utf-8')
            body = json.loads(mybody)
            if not addpresc_validator.validate(body):
                return HttpResponse('{"status":"Bad json"}', content_type='aplication/json')
            print(body['pet'])
            if body['pet'] != 0:

                pet = Pet.objects.get(id=body['pet'])
            else:
                if body['newPet']['owner'] != 0:
                    owner = Owner.objects.get(id=body['newPet']['owner'])
                else:
                    owner = Owner.objects.create(
                        first_name=body['newPet']['newOwner']['first_name'],
                        last_name=body['newPet']['newOwner']['last_name'],
                        email=body['newPet']['newOwner']['email'],
                        phone_number=body['newPet']['newOwner']['phone_number'],
                    )
                    owner.save()

                if not Species.objects.filter(species_name=body['newPet']['species']):
                    species = Species.objects.create(species_name=body['newPet']['species'], additional_information='')
                    species.save()
                else:
                    species = Species.objects.get(species_name=body['newPet']['species'])

                pet = Pet.objects.create(
                    name=body['newPet']['name'],
                    date_of_birth=datetime.strptime(body['newPet']['date_of_birth'], '%Y-%m-%d'),
                    sex=body['newPet']['sex'],
                    species=species,
                    additional_information=body['newPet']['additional_information'],
                    owner=owner
                )
                pet.save()

            pre = Prescription.objects.create(
                code=body['code'],
                issue_date=datetime.now(),
                expiration_date=datetime.strptime(body['expiration_date'], '%Y-%m-%d'),
                pet=pet,
                vet=vet,
                owner=pet.owner,
                status='Wystawiona'
            )
            pre.save()

            for c in body['cures']:
                mcure = Cure.objects.get(id=c['cure'])
                quantity = c['quantity']
                q_type = c['quantity_type']

                mycure = PrescriptionCure.objects.create(
                    quantity=quantity,
                    quantity_type=q_type,
                    cure=mcure,
                    prescription=pre
                )
                mycure.save()

            return HttpResponse('{"status":"ok"}', content_type='aplication/json')

    else:
        return redirect('signin')


def prescription(request, prescid):
    if request.session.get('my_user', False):
        try:
            prescription = Prescription.objects.get(id=prescid)
            cures = PrescriptionCure.objects.filter(prescription__id=prescid).all()

            if prescription.expiration_date < datetime.now().date() and prescription.status == 'Wystawiona':
                prescription.status = 'Wygasla'
                prescription.save()

            return render(request, 'klinika/prescription.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Podgląd recepty',
                           'presc': prescription,
                           'cures': cures,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except:
            return render(request, 'klinika/prescription.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak danych recepty!',
                           'title': 'Podgląd recepty',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


# endregion

# region treatment
def treatments(request, petid):
    if request.session.get('my_user', False):
        try:
            med = Treatment.objects.filter(pet__id=petid).all()
            pet = Pet.objects.get(id=petid)
            return render(request, 'klinika/treatments.html',
                          {'username': request.session.get('my_user'),
                           'med': med,
                           'pet': pet,
                           'error': False,
                           'title': 'Historia leczenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except:
            return render(request, 'klinika/treatments.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak danych medycznych zwierzęcia!',
                           'title': 'Historia leczenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def addtreatment(request, petid):
    if request.session.get('my_user', False):
        pet = Pet.objects.get(id=petid)

        if request.method == 'GET':
            return render(request, 'klinika/addtreatment.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Dodawanie leczenia',
                           'pet': pet,
                           'error': False,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        if request.method == 'POST':
            date_time_treatment = bleach.clean(request.POST['date_time_treatment'])
            desc = bleach.clean(request.POST['description'])

            treat = Treatment.objects.create(
                date_time_treatment=date_time_treatment,
                pet=pet,
                description=desc
            )
            treat.save()

            return redirect('treatments', petid=petid)
    else:
        return redirect('signin')


def treatment(request, petid, treatid):
    if request.session.get('my_user', False):
        try:
            pet = Pet.objects.get(id=petid)
            treat = Treatment.objects.get(id=treatid, pet=pet)

            if request.method == "POST":
                if request.POST['type'] == 'description':
                    description = bleach.clean(request.POST['description'])
                    treat.description = description
                    treat.save()

        except():
            return render(request, 'klinika/treatment.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono historii medycznej!',
                           'title': 'Podgląd leczenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/treatment.html/',
                      {'username': request.session.get('my_user'),
                       'treat': treat,
                       'error': False,
                       'title': 'Podgląd leczenia',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


# endregion

# region Administration

def usersmanagement(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()
        if any(x.user_type == 'ADMIN' for x in utypes):
            users = MyUser.objects.filter().all()

            return render(request, 'klinika/users.html',
                          {'username': request.session.get('my_user'),
                           'users': users,
                           'title': 'Zarządzanie użytkownikami',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        else:
            return render(request, 'klinika/users.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie użytkownikami',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

    else:
        return redirect('signin')


def usermanagement(request, uid):
    if request.session.get('my_user', False):
        try:
            user = MyUser.objects.get(id=uid)
            enum = UserTypeEnum.__members__.keys()
            myuser = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=myuser).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                if UserType.objects.filter(user=user).exists():
                    utypes2 = UserType.objects.filter(user=user).all()
                    utypes2_msg = ''
                    nothing = False
                else:
                    nothing = True
                    utypes2 = UserType.objects.filter(user=user).all()
                    utypes2_msg = 'Użytkownik nie ma żadnych uprawnień!\nNadaj mu odpowiedni typ w celu nadania uprawnień'
                if UserAddresses.objects.filter(user=user).exists():
                    uaddresses = UserAddresses.objects.filter(user=user).all()
                    uaddress = UserAddresses.objects.get(user=user, current=True)
                    uaddresses_msg = ''
                    uaddress_msg = ''
                    nothing2 = False
                else:
                    uaddresses = UserAddresses.objects.filter(user=user).all()
                    uaddress = UserAddresses.objects.filter(user=user, current=True).all()
                    nothing2 = True
                    uaddresses_msg = 'Brak adresów do wyświetlenia!'
                    uaddress_msg = 'Brak miejsca zamieszkania!'

                if request.method == "POST":

                    if request.POST['type'] == 'first_name':
                        fname = bleach.clean(request.POST['first_name'])

                        if Owner.objects.filter(user=user).exists():
                            owner = Owner.objects.get(user=user)
                            owner.first_name = fname
                            owner.save()

                        user.first_name = fname
                        user.save()

                    if request.POST['type'] == 'last_name':
                        lname = bleach.clean(request.POST['last_name'])

                        if Owner.objects.filter(user=user).exists():
                            owner = Owner.objects.get(user=user)
                            owner.last_name = lname
                            owner.save()

                        user.last_name = lname
                        user.save()

                    if request.POST['type'] == 'password':
                        pass1 = bleach.clean(request.POST['pass1'])
                        pass2 = bleach.clean(request.POST['pass2'])
                        if pass1 == pass2:
                            password = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())
                            user.password = password
                            user.save()

                    if request.POST['type'] == 'phone_number':
                        phone = bleach.clean(request.POST['phone_number'])
                        user.phone_number = phone
                        user.save()

                    if request.POST['type'] == 'email':
                        email = bleach.clean(request.POST['email'])
                        user.email = email
                        user.save()

                    if request.POST['type'] == "role":
                        for e in enum:
                            current_role = 'role-{}'.format(e)
                            if user.username == request.session.get('my_user', False) and e == 'ADMIN':
                                pass
                            else:
                                arole = request.POST.get(current_role, None)
                                if arole == 'on':
                                    if any(x.user_type == e for x in utypes2):
                                        pass
                                    else:
                                        utype2 = UserType.objects.create(
                                            user=user,
                                            user_type=e
                                        )
                                        utype2.save()
                                else:
                                    if any(x.user_type == e for x in utypes):
                                        if UserType.objects.filter(user=user, user_type=e).exists():
                                            UserType.objects.get(user=user, user_type=e).delete()
                            utypes2 = UserType.objects.filter(user=user).all()

                    if request.POST['type'] == 'chaddress':
                        if request.POST['addresses'] == 'Dodaj':
                            address = bleach.clean(request.POST['address'])
                            uaddress.current = False
                            uaddress.save()
                            newaddress = UserAddresses.objects.create(
                                user=user,
                                address=address,
                                current=True
                            )
                            newaddress.save()
                        else:
                            address = UserAddresses.objects.get(id=request.POST['addresses'])
                            uaddress.current = False
                            uaddress.save()
                            address.current = True
                            address.save()

                    user = MyUser.objects.get(id=uid)
                    uaddress = UserAddresses.objects.get(user=user, current=True)

                return render(request, 'klinika/user.html', {'username': request.session.get('my_user'),
                                                             'user': user,
                                                             'title': 'Zarządzanie użytkownikiem',
                                                             'enum': enum,
                                                             'utypes': utypes2,
                                                             'utypes_msg': utypes2_msg,
                                                             'uaddresses': uaddresses,
                                                             'uaddress': uaddress,
                                                             'uaddresses_msg': uaddresses_msg,
                                                             'uaddress_msg': uaddress_msg,
                                                             'nothing': nothing,
                                                             'nothing2': nothing2,
                                                             'adm': request.session.get('is_adm'),
                                                             'vet': request.session.get('is_vet'),
                                                             'rec': request.session.get('is_rec'),
                                                             'own': request.session.get('is_own'),
                                                             })
        except():
            return render(request, 'klinika/user.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie użytkownikiem',
                           'error': 'Nie znaleziono użytkownika',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/user.html',
                      {'username': request.session.get('my_user'),
                       'title': 'Zarządzanie użytkownikiem',
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def useraddress(request, uaddress):
    if request.session.get('my_user', False):
        try:
            user = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=user).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                address = UserAddresses.objects.get(id=uaddress)

                if request.method == "POST":

                    if request.POST['type'] == 'address':
                        newaddress = bleach.clean(request.POST['address'])
                        if not UserAddresses.objects.filter(address=newaddress, user=address.user).exists():
                            address.address = newaddress
                            address.save()
                        else:
                            return render(request, 'klinika/species.html', {'username': request.session.get('my_user'),
                                                                            'address': address,
                                                                            'title': 'Zarządzanie adresem użytkownika',
                                                                            'error1': 'Podany adres już '
                                                                                      'istnieje dla tego użytkownika!',
                                                                            'adm': request.session.get('is_adm'),
                                                                            'vet': request.session.get('is_vet'),
                                                                            'rec': request.session.get('is_rec'),
                                                                            'own': request.session.get('is_own'),
                                                                            })

                    if request.POST['type'] == 'current':
                        if request.POST.get("current", None):
                            address.current = True
                        else:
                            address.current = False

                        address.save()

                    address = UserAddresses.objects.get(id=uaddress)

                return render(request, 'klinika/useraddress.html', {'username': request.session.get('my_user'),
                                                                    'address': address,
                                                                    'title': 'Zarządzanie adresem użytkownika',
                                                                    'adm': request.session.get('is_adm'),
                                                                    'vet': request.session.get('is_vet'),
                                                                    'rec': request.session.get('is_rec'),
                                                                    'own': request.session.get('is_own'),
                                                                    })
        except():
            return render(request, 'klinika/useraddress.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono adresu',
                           'title': 'Zarządzanie adresem użytkownika',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def userdeactivation(request, uid):
    if request.session.get('my_user', False):
        if MyUser.objects.filter(id=uid).exists():
            user = MyUser.objects.get(id=uid)
            myuser = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=myuser).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                user.is_active = False
                user.save()

                return redirect('usermanagement', uid=uid)
        return redirect('')
    return redirect('signin')


def userreactivation(request, uid):
    if request.session.get('my_user', False):
        if MyUser.objects.filter(id=uid).exists():
            user = MyUser.objects.get(id=uid)
            myuser = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=myuser).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                user.is_active = True
                user.save()

                return redirect('usermanagement', uid=uid)
        return redirect('')
    return redirect('signin')


def usermanagementadd(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()
        enum = UserTypeEnum.__members__.keys()
        if any(x.user_type == 'ADMIN' for x in utypes):

            if request.method == "POST":
                uname = bleach.clean(request.POST['username'])
                pass1 = bleach.clean(request.POST['pass1'])
                pass2 = bleach.clean(request.POST['pass2'])
                fname = bleach.clean(request.POST['first_name'])
                lname = bleach.clean(request.POST['last_name'])
                email = bleach.clean(request.POST['email'])
                phone = bleach.clean(request.POST['phone_number'])
                address = bleach.clean(request.POST['address'])
                note = bleach.clean(request.POST['note'])

                if pass1 == pass2:
                    passwd = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())
                else:
                    return render(request, 'klinika/useradd.html',
                                  {'username': request.session.get('my_user'),
                                   'error': 'Nieprawidłowe hasło!',
                                   'title': 'Zarządzanie - dodawanie użytkownika',
                                   'adm': request.session.get('is_adm'),
                                   'vet': request.session.get('is_vet'),
                                   'rec': request.session.get('is_rec'),
                                   'own': request.session.get('is_own'),
                                   })

                newuser = MyUser.objects.create(
                    username=uname,
                    password=passwd,
                    first_name=fname,
                    last_name=lname,
                    email=email,
                    phone_number=phone,
                    is_active=True,
                    note=note
                )
                newuser.save()

                newaddress = UserAddresses.objects.create(
                    user=newuser,
                    address=address,
                    current=True
                )
                newaddress.save()

                if request.POST['type'] == "role":
                    newuser = MyUser.objects.get(email=email)
                    for e in enum:
                        current_role = 'role-{}'.format(e)
                        arole = request.POST.get(current_role, None)
                        if arole == 'on':
                            utype = UserType.objects.create(
                                user=newuser,
                                user_type=e
                            )
                            utype.save()

            return render(request, 'klinika/useradd.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie - dodawanie użytkownika',
                           'enum': enum,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        else:
            return render(request, 'klinika/useradd.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie - dodawanie użytkownika',
                           'error': 'Brak uprawnień',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

    else:
        return redirect('signin')


def petsmanagement(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()
        if any(x.user_type == 'ADMIN' for x in utypes):
            pets = Pet.objects.filter().all()
            species = Species.objects.filter().all()
            if species.count() == 0:
                return render(request, 'klinika/pets.html',
                              {'username': request.session.get('my_user'),
                               'empty': True,
                               'title': 'Zarządzanie zwierzętami',
                               'admin': True,
                               'pet_list': 'Brak zwierząt do wyświetlenia',
                               'species': 'Brak gatunków do wyświetlenia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            if pets.count() == 0:
                return render(request, 'klinika/pets.html',
                              {'username': request.session.get('my_user'),
                               'empty': True,
                               'title': 'Zarządzanie zwierzętami',
                               'admin': True,
                               'species': species,
                               'pet_list': 'Brak zwierząt do wyświetlenia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            return render(request, 'klinika/pets.html',
                          {'username': request.session.get('my_user'),
                           'admin': True,
                           'title': 'Zarządzanie zwierzętami',
                           'pet_list': pets,
                           'species': species,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def petmanagement(request, petid):
    if request.session.get('my_user', False):
        try:
            user = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=user).all()
            vets = UserType.objects.filter(user_type='VET').all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                pet = Pet.objects.get(id=petid)
                owners = UserType.objects.filter(user_type='PET_OWNER').all()
                if Visit.objects.filter(pet__id=petid, status='Zaplanowana').exists():
                    recdate = Visit.objects.filter(pet__id=petid,
                                                   status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                    visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])
                    nothing = False
                else:
                    nothing = True
                    visit = 'Brak wizyt do wyświetlenia!'
                if Prescription.objects.filter(pet__id=petid, status='Wystawiona').exists():
                    recexpdate = Prescription.objects.filter(pet__id=petid,
                                                             status='Wystawiona').aggregate(
                        expiration_date=Min('expiration_date'))
                    prescription = Prescription.objects.get(pet__id=petid, status='Wystawiona',
                                                            expiration_date=recexpdate['expiration_date'])

                    cures = PrescriptionCure.objects.filter(prescription__id=prescription.id).all()

                    nothing2 = False
                else:
                    nothing2 = True
                    prescription = 'Brak recept do wyświetlenia!'
                    cures = 'Brak leków do wyświetlenia!'

                if request.method == "POST":

                    if request.POST['type'] == 'name':
                        name = bleach.clean(request.POST['name'])
                        pet.name = name
                        pet.save()

                    if request.POST['type'] == 'date_of_birth':
                        date_of_birth = bleach.clean(request.POST['date_of_birth'])
                        pet.date_of_birth = date_of_birth
                        pet.save()

                    if request.POST['type'] == 'sex':
                        sex = bleach.clean(request.POST['sex'])
                        pet.sex = sex
                        pet.save()

                    if request.POST['type'] == 'species':
                        species = bleach.clean(request.POST['species'])
                        pet.species = species
                        pet.save()

                    if request.POST['type'] == 'additional_information':
                        additional_information = bleach.clean(request.POST['additional_information'])
                        pet.additional_information = additional_information
                        pet.save()
                    if request.POST['type'] == 'owner':
                        if request.POST['own'] == 'Dodaj':
                            first_name = bleach.clean(request.POST['first_name'])
                            last_name = bleach.clean(request.POST['last_name'])
                            phone_number = bleach.clean(request.POST['phone_number'])
                            email = bleach.clean(request.POST['email'])

                            owner = Owner.objects.create(
                                first_name=first_name,
                                last_name=last_name,
                                phone_number=phone_number,
                                email=email)

                            owner.save()
                        else:
                            user = MyUser.objects.get(email=request.POST['own'])
                            if not Owner.objects.filter(user=user).exists():
                                owner = Owner.objects.create(
                                    first_name=user.first_name,
                                    last_name=user.last_name,
                                    phone_number=user.phone_number,
                                    email=user.email,
                                    user=user
                                )
                                owner.save()
                            owner = Owner.objects.get(user=user)
                        pet.owner = owner
                        pet.save()

                    if request.POST['type'] == 'visit_date':
                        visit_date = bleach.clean(request.POST['visit_date'])
                        visit.visit_date = visit_date
                        visit.save()

                        recdate = Visit.objects.filter(pet__id=petid,
                                                       status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                        visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])

                    if request.POST['type'] == 'visit_time':
                        visit_time = bleach.clean(request.POST['visit_time'])
                        visit.visit_time = visit_time
                        visit.save()

                        recdate = Visit.objects.filter(pet__id=petid,
                                                       status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                        visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])

                    if request.POST['type'] == 'vet':
                        vet = MyUser.objects.get(email=request.POST['vet'])
                        visit.vet = vet
                        visit.save()

                        recdate = Visit.objects.filter(pet__id=petid,
                                                       status='Zaplanowana').aggregate(visit_date=Min('visit_date'))
                        visit = Visit.objects.get(pet__id=petid, status='Zaplanowana', visit_date=recdate['visit_date'])

                    pet = Pet.objects.get(id=petid)

                return render(request, 'klinika/pet.html', {'username': request.session.get('my_user'),
                                                            'pet': pet,
                                                            'title': 'Zarządzanie zwierzęciem',
                                                            'vets': vets,
                                                            'owners': owners,
                                                            'admin': True,
                                                            'visit': visit,
                                                            'presc': prescription,
                                                            'cures': cures,
                                                            'nothing': nothing,
                                                            'nothing2': nothing2,
                                                            'adm': request.session.get('is_adm'),
                                                            'vet': request.session.get('is_vet'),
                                                            'rec': request.session.get('is_rec'),
                                                            'own': request.session.get('is_own'),
                                                            })

        except:
            return render(request, 'klinika/pet.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono zwierzęcia',
                           'title': 'Zarządzanie zwierzęciem',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pet.html', {'username': request.session.get('my_user'),
                                                    'adm': request.session.get('is_adm'),
                                                    'title': 'Zarządzanie zwierzęciem',
                                                    'vet': request.session.get('is_vet'),
                                                    'rec': request.session.get('is_rec'),
                                                    'own': request.session.get('is_own'),
                                                    })
    else:
        return redirect('signin')


def speciesmanagement(request, speciesid):
    if request.session.get('my_user', False):
        try:
            user = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=user).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                species = Species.objects.get(id=speciesid)

                if request.method == "POST":

                    if request.POST['type'] == 'species_name':
                        name = bleach.clean(request.POST['species_name'])
                        if not Species.objects.filter(species_name=name.lower()).exists():
                            species.species_name = name
                            species.save()
                        else:
                            return render(request, 'klinika/species.html', {'username': request.session.get('my_user'),
                                                                            'species': species,
                                                                            'title': 'Zarządzanie gatunkiem zwierząt',
                                                                            'error1': 'Podana nazwa gatunku jest już '
                                                                                      'zajęta!',
                                                                            'adm': request.session.get('is_adm'),
                                                                            'vet': request.session.get('is_vet'),
                                                                            'rec': request.session.get('is_rec'),
                                                                            'own': request.session.get('is_own'),
                                                                            })

                    if request.POST['type'] == 'additional_information':
                        ainfo = bleach.clean(request.POST['additional_information'])
                        species.additional_information = ainfo
                        species.save()

                    species = Species.objects.get(id=speciesid)

                return render(request, 'klinika/species.html', {'username': request.session.get('my_user'),
                                                                'species': species,
                                                                'title': 'Zarządzanie gatunkiem zwierząt',
                                                                'adm': request.session.get('is_adm'),
                                                                'vet': request.session.get('is_vet'),
                                                                'rec': request.session.get('is_rec'),
                                                                'own': request.session.get('is_own'),
                                                                })
        except():
            return render(request, 'klinika/species.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono gatunku',
                           'title': 'Zarządzanie gatunkiem zwierząt',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def speciesmanagementadd(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()

        if any(x.user_type == 'ADMIN' for x in utypes):

            if request.method == "POST":
                name = bleach.clean(request.POST['species_name'])
                ainfo = bleach.clean(request.POST['additional_information'])

                if Species.objects.filter(species_name=name).exists():
                    return render(request, 'klinika/speciesadd.html', {'username': request.session.get('my_user'),
                                                                       'error1': 'Podana nazwa gatunku jest już '
                                                                                 'zajęta!',
                                                                       'title': 'Zarządzanie - Dodawanie gatunku zwierząt',
                                                                       'adm': request.session.get('is_adm'),
                                                                       'vet': request.session.get('is_vet'),
                                                                       'rec': request.session.get('is_rec'),
                                                                       'own': request.session.get('is_own'),
                                                                       })

                species = Species.objects.create(
                    species_name=name,
                    additional_information=ainfo
                )
                species.save()

            return render(request, 'klinika/speciesadd.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie - Dodawanie gatunku zwierząt',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        else:
            return render(request, 'klinika/speciesadd.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak uprawnień',
                           'title': 'Zarządzanie - Dodawanie gatunku zwierząt',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

    else:
        return redirect('signin')


def treatmentsmanagement(request, petid):
    if request.session.get('my_user', False):
        try:
            med = Treatment.objects.filter(pet__id=petid).all()
            pet = Pet.objects.get(id=petid)
            return render(request, 'klinika/treatments.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie historią leczenia',
                           'med': med,
                           'pet': pet,
                           'error': False,
                           'admin': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except():
            return render(request, 'klinika/treatments.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie historią leczenia',
                           'error': 'Brak danych medycznych zwierzęcia!',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def treatmentmanagement(request, petid, treatid):
    if request.session.get('my_user', False):
        try:
            pet = Pet.objects.get(id=petid)
            treat = Treatment.objects.get(id=treatid, pet=pet)

            if request.method == "POST":

                if request.POST['type'] == 'date_time_treatment':
                    dt_treatment = bleach.clean(request.POST['date_time_treatment'])
                    treat.date_time_treatment = dt_treatment
                    treat.save()

                if request.POST['type'] == 'description':
                    description = bleach.clean(request.POST['description'])
                    treat.description = description
                    treat.save()

                treat = Treatment.objects.get(id=treatid, pet=pet)


        except():
            return render(request, 'klinika/treatment.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono historii medycznej!',
                           'title': 'Zarządzanie leczeniem',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/treatment.html/',
                      {'username': request.session.get('my_user'),
                       'treat': treat,
                       'title': 'Zarządzanie leczeniem',
                       'admin': True,
                       'error': False,
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


def visitsmanagement(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()
        if any(x.user_type == 'ADMIN' for x in utypes):
            visits = Visit.objects.filter().all()
            if visits.count() == 0:
                return render(request, 'klinika/visit.html',
                              {'username': request.session.get('my_user'),
                               'empty': True,
                               'title': 'Zarządzanie wizytami',
                               'visit_list': 'Brak wizyt do wyświetlenia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            return render(request, 'klinika/visit.html',
                          {'username': request.session.get('my_user'),
                           'visit_list': visits,
                           'title': 'Zarządzanie wizytami',
                           'admin': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def visitmanagement(request, visitid):
    if request.session.get('my_user', False):
        try:
            visit = Visit.objects.get(id=visitid)
            status = visit.status

            if status == 'Odbyta':
                if Prescription.objects.filter(pet__id=visit.pet.id, status='Wystawiona').exists():
                    recexpdate = Prescription.objects.filter(pet_id=visit.pet.id,
                                                             status='Wystawiona').aggregate(
                        expiration_date=Min('expiration_date'))
                    prescription = Prescription.objects.get(pet__id=visit.pet.id, status='Wystawiona',
                                                            expiration_date=recexpdate['expiration_date'])

                    cures = PrescriptionCure.objects.filter(prescription__id=prescription.id).all()

                    nothing = False
                else:
                    nothing = True
                    prescription = 'Brak recept do wyświetlenia!'
                    cures = 'Brak leków do wyświetlenia!'

                if Treatment.objects.filter(pet__id=visit.pet.id).exists():
                    recdttreat = Treatment.objects.filter(pet__id=visit.pet.id).aggregate(
                        date_time_treatment=Min('date_time_treatment'))
                    treatment = Treatment.objects.get(pet__id=visit.pet.id,
                                                      date_time_treatment=recdttreat['date_time_treatment'])
                    nothing2 = False
                else:
                    nothing2 = True
                    treatment = 'Brak historii leczenia do wyświetlenia!'
            else:
                nothing = True
                prescription = 'Brak recept do wyświetlenia!'
                cures = 'Brak leków do wyświetlenia!'
                nothing2 = True
                treatment = 'Brak historii leczenia do wyświetlenia!'

            if request.method == 'POST':
                if request.POST['type'] == 'visit_date':
                    visit_date = bleach.clean(request.POST['visit_date'])
                    visit.visit_date = visit_date
                    visit.save()

                if request.POST['type'] == 'visit_time':
                    visit_time = bleach.clean(request.POST['visit_time'])
                    visit.visit_time = visit_time
                    visit.save()

                if request.POST['type'] == 'status':
                    status = bleach.clean(request.POST['status'])
                    visit.status = status
                    visit.save()

                visit = Visit.objects.get(id=visitid)

            return render(request, 'klinika/the-visit.html',
                          {'username': request.session.get('my_user'),
                           'visit': visit,
                           'title': 'Zarządzanie wizytą',
                           'pastvisit': status,
                           'nothing': nothing,
                           'nothing2': nothing2,
                           'treat': treatment,
                           'presc': prescription,
                           'cures': cures,
                           'admin': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except:
            return render(request, 'klinika/the-visit.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak danych wizyty!',
                           'title': 'Zarządzanie wizytą',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def prescsmanagement(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()
        if any(x.user_type == 'ADMIN' for x in utypes):
            prescs = Prescription.objects.filter().all()
            cures = Cure.objects.filter().all()
            if prescs.count() == 0:
                return render(request, 'klinika/prescriptions.html',
                              {'username': request.session.get('my_user'),
                               'admin': True,
                               'empty': True,
                               'empty2': False,
                               'title': 'Zarządzanie receptami',
                               'rec_list': 'Brak recept do wyświetlenia',
                               'cures': cures,
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if cures.count() == 0:
                return render(request, 'klinika/prescriptions.html',
                              {'username': request.session.get('my_user'),
                               'admin': True,
                               'empty': True,
                               'empty2': True,
                               'title': 'Zarządzanie receptami',
                               'cures': 'Brak leków do wyświetlenia',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            return render(request, 'klinika/prescriptions.html',
                          {'username': request.session.get('my_user'),
                           'admin': True,
                           'title': 'Zarządzanie receptami',
                           'rec_list': prescs,
                           'cures': cures,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def prescmanagement(request, prescid):
    if request.session.get('my_user', False):
        try:
            prescription = Prescription.objects.get(id=prescid)
            cures = PrescriptionCure.objects.filter(prescription__id=prescid).all()

            if prescription.expiration_date < datetime.date(datetime.now()) and prescription.status == 'Wystawiona':
                prescription.status = 'Wygasla'
                prescription.save()

            if request.method == "POST":

                if request.POST['type'] == 'status':
                    status = bleach.clean(request.POST['status'])
                    prescription.status = status
                    prescription.save()

                prescription = Prescription.objects.get(id=prescid)

            return render(request, 'klinika/prescription.html',
                          {'username': request.session.get('my_user'),
                           'presc': prescription,
                           'title': 'Zarządzanie receptą',
                           'cures': cures,
                           'admin': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        except:
            return render(request, 'klinika/prescription.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Brak danych recepty!',
                           'title': 'Zarządzanie receptą',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def curemanagement(request, cureid):
    if request.session.get('my_user', False):
        try:
            user = MyUser.objects.get(username=request.session.get('my_user', False))
            utypes = UserType.objects.filter(user=user).all()
            if any(x.user_type == 'ADMIN' for x in utypes):
                cure = Cure.objects.get(id=cureid)

                if request.method == "POST":

                    if request.POST['type'] == 'name':
                        name = bleach.clean(request.POST['name'])
                        if not Cure.objects.filter(name=name, dose=cure.dose, dose_type=cure.dose_type).exists():
                            cure.name = name
                            cure.save()
                        else:
                            return render(request, 'klinika/cure.html', {'username': request.session.get('my_user'),
                                                                         'cure': cure,
                                                                         'title': 'Zarządzanie lekiem',
                                                                         'error1': 'Podany lek już istnieje!',
                                                                         'adm': request.session.get('is_adm'),
                                                                         'vet': request.session.get('is_vet'),
                                                                         'rec': request.session.get('is_rec'),
                                                                         'own': request.session.get('is_own'),
                                                                         })
                    if request.POST['type'] == 'dose':
                        dose = bleach.clean(request.POST['dose'])
                        if not Cure.objects.filter(name=cure.name, dose=dose, dose_type=cure.dose_type).exists():
                            cure.dose = dose
                            cure.save()
                        else:
                            return render(request, 'klinika/cure.html', {'username': request.session.get('my_user'),
                                                                         'cure': cure,
                                                                         'title': 'Zarządzanie lekiem',
                                                                         'error1': 'Podany lek już istnieje!',
                                                                         'adm': request.session.get('is_adm'),
                                                                         'vet': request.session.get('is_vet'),
                                                                         'rec': request.session.get('is_rec'),
                                                                         'own': request.session.get('is_own'),
                                                                         })
                    if request.POST['type'] == 'dose_type':
                        dose_type = bleach.clean(request.POST['dose_type'])
                        if not Cure.objects.filter(name=cure.name, dose=cure.dose, dose_type=dose_type).exists():
                            cure.dose_type = dose_type
                            cure.save()
                        else:
                            return render(request, 'klinika/cure.html', {'username': request.session.get('my_user'),
                                                                         'cure': cure,
                                                                         'title': 'Zarządzanie lekiem',
                                                                         'error1': 'Podany lek już istnieje!',
                                                                         'adm': request.session.get('is_adm'),
                                                                         'vet': request.session.get('is_vet'),
                                                                         'rec': request.session.get('is_rec'),
                                                                         'own': request.session.get('is_own'),
                                                                         })

                    cure = Cure.objects.get(id=cureid)

                return render(request, 'klinika/cure.html', {'username': request.session.get('my_user'),
                                                             'cure': cure,
                                                             'title': 'Zarządzanie lekiem',
                                                             'adm': request.session.get('is_adm'),
                                                             'vet': request.session.get('is_vet'),
                                                             'rec': request.session.get('is_rec'),
                                                             'own': request.session.get('is_own'),
                                                             })
        except():
            return render(request, 'klinika/cure.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono leku',
                           'title': 'Zarządzanie lekiem',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
    else:
        return redirect('signin')


def curemanagementadd(request):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        utypes = UserType.objects.filter(user=user).all()

        if any(x.user_type == 'ADMIN' for x in utypes):

            if request.method == "POST":
                name = bleach.clean(request.POST['name'])
                dose_type = bleach.clean(request.POST['dose_type'])
                dose = bleach.clean(request.POST['dose'])

                if Cure.objects.filter(name=name, dose_type=dose_type, dose=dose).exists():
                    return render(request, 'klinika/cureadd.html', {'username': request.session.get('my_user'),
                                                                    'title': 'Zarządzanie - Dodawanie leku',
                                                                    'error1': 'Podany lek już istnieje!',
                                                                    'adm': request.session.get('is_adm'),
                                                                    'vet': request.session.get('is_vet'),
                                                                    'rec': request.session.get('is_rec'),
                                                                    'own': request.session.get('is_own'),
                                                                    })

                cure = Cure.objects.create(
                    name=name,
                    dose_type=dose_type,
                    dose=dose
                )
                cure.save()

            return render(request, 'klinika/cureadd.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie - Dodawanie leku',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })
        else:
            return render(request, 'klinika/cureadd.html',
                          {'username': request.session.get('my_user'),
                           'title': 'Zarządzanie - Dodawanie leku',
                           'error': 'Brak uprawnień',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

    else:
        return redirect('signin')


# endregion
# region setup

def setup(request):
    global mytype
    if MyUser.objects.count() == 0:
        if request.method == "GET":
            return render(request, 'klinika/setup.html')
        if request.method == "POST":
            uname = request.POST['username']
            fname = request.POST['first_name']
            lname = request.POST['last_name']
            email = request.POST['email']
            pass1 = request.POST['pass1']
            pass2 = request.POST['pass2']

            if len(uname) > 30:
                return render(request, 'klinika/signup.html', {'error1': "Podana nazwa uzytkownika jest za dluga!",
                                                               'title': 'Konfiguracja aplikacji'
                                                               })
            if not uname.isalnum():
                return render(request, 'klinika/signup.html',
                              {'error2': "Nazwa użytkownika musi się składać z liter oraz cyfr!",
                               'title': 'Konfiguracja aplikacji'
                               })

            regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

            if not re.search(regex, email):
                return render(request, 'klinika/signup.html', {'error3': "Nieprawidłowy adress email!",
                                                               'title': 'Konfiguracja aplikacji'
                                                               })
            if pass1 != pass2:
                messages.error(request, "Hasła muszą się zgadzać!")
                return render(request, 'klinika/signup.html', {'error4': "Hasła muszą się zgadzać!",
                                                               'title': 'Konfiguracja aplikacji'
                                                               })

            passwd = bcrypt.hashpw(pass1.encode(encoding='UTF-8'), bcrypt.gensalt())

            admin = MyUser.objects.create(username=uname,
                                          first_name=fname,
                                          last_name=lname,
                                          email=email,
                                          password=passwd,
                                          is_active=True)
            admin.save()
            for utype in UserTypeEnum.__members__.keys():
                mytype = UserType.objects.create(user=admin, user_type=utype)
            mytype.save()
        return render(request, 'klinika/setup.html', {'confirmation': 'Administrator utworzony pomyślnie!',
                                                      'title': 'Konfiguracja aplikacji'
                                                      })
    return redirect('VetPet')

# endregion
