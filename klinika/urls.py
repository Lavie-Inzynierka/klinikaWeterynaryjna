from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name="VetPet"),
    path('setup/', views.setup, name="setup"),
    path('about/', views.about, name="about"),
    path('signup/', views.signup, name="signup"),
    path('activate/<token>/', views.VerificationView, name="activate"),
    path('signin/', views.signin, name="signin"),
    path('profile/', views.profile, name="profile"),
    path('signout/', views.signout, name="signout"),
    path('mypets/', views.mypets, name="mypets"),
    path('mypet/<petid>/', views.mypet, name="mypet"),
    path('addpet/', views.addpet, name="addpet"),
    path('pets/', views.pets, name="pets"),
    path('addpets/', views.addpets, name="addpets"),
    path('pet/<petid>/', views.pet, name="pet"),
    path('allvisits/', views.allvisits, name="allvisits"),
    path('myvisits/', views.myvisits, name="myvisits"),
    path('upcomvisits/', views.upcomvisits, name="upcomvisits"),
    path('visits/', views.visits, name="visits"),
    path('canceledvisits/', views.canceledvisits, name="canceledvisits"),
    path('addvisit/', views.addvisit, name="addvisit"),

]
