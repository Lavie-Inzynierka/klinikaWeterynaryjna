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
    return render(request, 'klinika/signin.html')


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
                return render(request, 'klinika/signup.html', {'error1': "Nazwa użytkownika jest już zajęta!"})
            if MyUser.objects.filter(email=email).exists():
                return render(request, 'klinika/signup.html', {'error2': "Podany adres email jest już zajęty!"})

            if len(username) > 30:
                return render(request, 'klinika/signup.html', {'error3': "Podana nazwa uzytkownika jest za dluga!"})

            if pass1 != pass2:
                messages.error(request, "Hasła muszą się zgadzać!")
                return render(request, 'klinika/signup.html', {'error4': "Hasła muszą się zgadzać!"})

            if not username.isalnum():
                return render(request, 'klinika/signup.html',
                              {'error4': "Nazwa użytkownika musi się składać z liter oraz cyfr!"})

            regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

            if not re.search(regex, email):
                return render(request, 'klinika/signup.html', {'error6': "Nieprawidłowy adress email!"})

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

            return render(request, 'klinika/signup.html', {'success': "Konto utworzone pomyślnie!"})

        return render(request, 'klinika/signup.html')

    return render(request, 'klinika/signup.html', {'system_error': "Skonfiguruj aplikacje!"})


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
                                                                        'adm': request.session.get('is_adm'),
                                                                        'vet': request.session.get('is_vet'),
                                                                        'rec': request.session.get('is_rec'),
                                                                        'own': request.session.get('is_own'),
                                                                        })

                    return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                    'usr': user,
                                                                    'adr': user_adress.address,
                                                                    'error': 'Nieprawidłowe hasło/a!',
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
                                                                        'adm': request.session.get('is_adm'),
                                                                        'vet': request.session.get('is_vet'),
                                                                        'rec': request.session.get('is_rec'),
                                                                        'own': request.session.get('is_own'),
                                                                        })

                    return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                                    'usr': user,
                                                                    'adr': user_adress.address,
                                                                    'error': 'Nieprawidłowy adres email!',
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
                                                            'adm': request.session.get('is_adm'),
                                                            'vet': request.session.get('is_vet'),
                                                            'rec': request.session.get('is_rec'),
                                                            'own': request.session.get('is_own'),
                                                            })

        return render(request, 'klinika/profile.html', {'username': request.session.get('my_user'),
                                                        'usr': user,
                                                        'adr': user_adress.address,
                                                        'adm': request.session.get('is_adm'),
                                                        'vet': request.session.get('is_vet'),
                                                        'rec': request.session.get('is_rec'),
                                                        'own': request.session.get('is_own'),
                                                        })
    else:
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
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pets.html',
                      {'username': request.session.get('my_user'),
                       'pet_list': allpets,
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
                                                    'adm': request.session.get('is_adm'),
                                                    'vet': request.session.get('is_vet'),
                                                    'rec': request.session.get('is_rec'),
                                                    'own': request.session.get('is_own'),
                                                    })
    else:
        return redirect('signin')


def addpets(request):
    if request.session.get('my_user', False):
        owners = UserType.objects.filter(user_type='PET_OWNER').all()
        if request.method == 'GET':
            return render(request, 'klinika/addpets.html', {'username': request.session.get('my_user'),
                                                            'owners': owners,
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
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Imię zwierzęcia jest zbyt długie',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if sex.capitalize() not in str(Gender_choices):
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa płeć!',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if not Species.objects.filter(species_name=species):
                species = Species.objects.create(species_name=species, additional_information='')
                species.save()

            if datetime.datetime.strptime(date_of_birth, '%Y-%m-%d') > datetime.datetime.now():
                return render(request, 'klinika/addpets.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa data urodzenia!',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            newspecies = Species.objects.get(species_name=species)

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
                owner = Owner.objects.create(
                    first_name=user.first_name,
                    last_name=user.last_name,
                    phone_number=user.phone_number,
                    email=user.email,
                    user=user
                )
                owner.save()

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
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pets.html',
                      {'username': request.session.get('my_user'),
                       'userpets': True,
                       'pet_list': pets,
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
                           'userpets': True,
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/pet.html', {'username': request.session.get('my_user'),
                                                    'pet': pet,
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
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if sex.capitalize() not in str(Gender_choices):
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowa płeć!',
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
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })
            if not Owner.objects.filter(user=user):
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
            # todo: zmienić redirect na render z message succes
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
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'visit_list': allvisit,
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
                           'visit_list': 'Brak wizyt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/visit.html',
                      {'username': request.session.get('my_user'),
                       'visit_list': allvisit,
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

            now = datetime.datetime.now()
            if datetime.datetime.strptime(visit_date + 'T' + visit_time, '%Y-%m-%dT%H:%M') < now:
                return render(request, 'klinika/addvisit.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Nieprawidłowy czas wizyty!',
                               'pets': pets,
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
                    owner = Owner.objects.create(
                        first_name=user.first_name,
                        last_name=user.last_name,
                        phone_number=user.phone_number,
                        email=user.email,
                        user=user
                    )
                    owner.save()
                name = bleach.clean(request.POST['name'])
                date_of_birth = bleach.clean(request.POST['date_of_birth'])
                sex = bleach.clean(request.POST['sex'])
                species = bleach.clean(request.POST['species'])
                additional_information = bleach.clean(request.POST['additional_information'])

                if not Species.objects.filter(species_name=species):
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
                                         visit_planned=datetime.datetime.now(),
                                         status='Zaplanowana',
                                         pet=pet,
                                         vet=vet,
                                         note=note)

            visit.save()
            # todo: zmienić redirect na render z message succes
            return redirect('allvisits')
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
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
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
                           'rec_list': 'Brak recept do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/prescriptions.html',
                      {'username': request.session.get('my_user'),
                       'rec_list': allprescriptions,
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
                return render(request, 'klinika/signup.html', {'error1': "Podana nazwa uzytkownika jest za dluga!"})

            if not uname.isalnum():
                return render(request, 'klinika/signup.html',
                              {'error2': "Nazwa użytkownika musi się składać z liter oraz cyfr!"})

            regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

            if not re.search(regex, email):
                return render(request, 'klinika/signup.html', {'error3': "Nieprawidłowy adress email!"})

            if pass1 != pass2:
                messages.error(request, "Hasła muszą się zgadzać!")
                return render(request, 'klinika/signup.html', {'error4': "Hasła muszą się zgadzać!"})

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
        return render(request, 'klinika/setup.html', {'confirmation': 'Administrator utworzony pomyślnie!'})
    return redirect('VetPet')

# endregion
