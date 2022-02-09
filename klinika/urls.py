from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name="VetPet"),
    path('about/', views.about, name="about"),
    path('signin/', views.signin, name="signin"),
    path('profile/', views.profile, name="profile"),
    path('setup/', views.setup, name="setup"),
    path('signup/', views.signup, name="signup"),
    path('signout/', views.signout, name="signout"),
    path('mypets/', views.mypets, name="mypets"),
    path('pets/', views.pets, name="pets"),
    path('addpets/', views.addpets, name="addpets"),
    path('allvisits/', views.allvisits, name="allvisits"),
    path('myvisits/', views.myvisits, name="myvisits"),
    path('upcomvisits/', views.upcomvisits, name="upcomvisits"),
    path('visits/', views.visits, name="visits"),
    path('canceledvisits/', views.canceledvisits, name="canceledvisits"),
    path('mypet/<petid>/', views.mypet, name="mypet"),
    path('addpet/', views.addpet, name="addpet"),
    path('addvisit/', views.addvisit, name="addvisit"),
    path('activate/<token>/', views.VerificationView, name="activate"),
]
