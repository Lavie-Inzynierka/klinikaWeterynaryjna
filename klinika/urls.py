from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name="VetPet"),
    path('about/', views.about, name="about"),
    path('signin/', views.signin, name="signin"),
    path('setup/', views.setup, name="setup"),
    path('signup/', views.signup, name="signup"),
    path('signout/', views.signout, name="signout"),
    path('mypets/', views.mypets, name="mypets"),
    path('mypet/<petid>/', views.mypet, name="mypet"),
    path('addpet/', views.addpet, name="addpet"),
    path('activate/<token>/', views.VerificationView, name="activate"),
]
