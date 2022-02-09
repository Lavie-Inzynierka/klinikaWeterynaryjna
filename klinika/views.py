import hashlib
import datetime
import os
import bleach
from django.contrib import messages
from .models import MyUser, Pet, Gender_choices, UserType, UserTypeEnum, Species, Owner, UserAddresses, Visit
from django.shortcuts import render, redirect
from sendgrid import SendGridAPIClient
import bcrypt
from klinika.models import Token
from django.contrib.sites.shortcuts import get_current_site
import re


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

# todo: zabezpieczenie przed stworzeniem useless usera gdy nie ma admina
#   error - aplikacja nie została skonfigurowana! Skonfiguruj aplikacje!
def signup(request):
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

        return render(request, 'klinika/signup.html', {'success': "Konto utworzone pomyślnie!"})

    return render(request, 'klinika/signup.html')


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

                user.first_name = fname
                user.save()

            if request.POST['type'] == 'last_name':
                lname = bleach.clean(request.POST['last_name'])

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
                user.phone_number = phone
                user.save()

            if request.POST['type'] == 'email':
                email = bleach.clean(request.POST['email'])
                regex = r"^[a-z_\.0-9]*@[a-z0-9\-]*\.[a-z]*$"

                if not re.search(regex, email):
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
            user_type = UserType.objects.get(user=user, user_type='PET_OWNER')
        except:
            return render(request, 'klinika/mypets.html',
                          {'username': request.session.get('my_user'),
                           'pet_list': 'Brak zwierząt do wyświetlenia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/mypets.html',
                      {'username': request.session.get('my_user'),
                       'pet_list': pets,
                       'utype': user_type.user_type,
                       'adm': request.session.get('is_adm'),
                       'vet': request.session.get('is_vet'),
                       'rec': request.session.get('is_rec'),
                       'own': request.session.get('is_own'),
                       })
    else:
        return redirect('signin')


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

            if datetime.datetime.strptime(date_of_birth, '%Y-%m-%d') > datetime.datetime.now():
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
            if not Owner.objects.filter(user=user):
                owner = Owner.objects.create(
                    first_name=user.first_name,
                    last_name=user.last_name,
                    phone_number=user.phone_number,
                    email=user.email,
                    user=user)

                owner.save()
            owner = Owner.objects.get(user=user)
            if not Owner.objects.filter(user=user, phone_number=owner.phone_number).exists():
                return render(request, 'klinika/addpet.html',
                              {'username': request.session.get('my_user'),
                               'error': 'Uzupełnij dane kontaktowe w swoim profilu przed dodatniem zwierzęcia!',
                               'adm': request.session.get('is_adm'),
                               'vet': request.session.get('is_vet'),
                               'rec': request.session.get('is_rec'),
                               'own': request.session.get('is_own'),
                               })

            if not UserType.objects.filter(user=user, user_type='PET_OWNER').exists():
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
            # todo: zmienić redirect na render z message succes
            return redirect('mypets')
    else:
        return redirect('signin')


def mypet(request, petid):
    if request.session.get('my_user', False):
        user = MyUser.objects.get(username=request.session.get('my_user', False))
        owner = Owner.objects.get(user=user)

        try:
            pet = Pet.objects.get(id=petid, owner=owner)
            if request.method == "POST":

                if request.POST['type'] == 'name':
                    name = bleach.clean(request.POST['name'])
                    if len(name) > 32:
                        return render(request, 'klinika/mypet.html',
                                      {'username': request.session.get('my_user'),
                                       'error': 'Imię zwierzęcia jest zbyt długie',
                                       'pet': pet,
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
            return render(request, 'klinika/mypet.html',
                          {'username': request.session.get('my_user'),
                           'error': 'Nie znaleziono zwierzęcia',
                           'adm': request.session.get('is_adm'),
                           'vet': request.session.get('is_vet'),
                           'rec': request.session.get('is_rec'),
                           'own': request.session.get('is_own'),
                           })

        return render(request, 'klinika/mypet.html', {'username': request.session.get('my_user'),
                                                      'pet': pet,
                                                      'adm': request.session.get('is_adm'),
                                                      'vet': request.session.get('is_vet'),
                                                      'rec': request.session.get('is_rec'),
                                                      'own': request.session.get('is_own'),
                                                      })
    else:
        return redirect('signin')


# endregion


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
