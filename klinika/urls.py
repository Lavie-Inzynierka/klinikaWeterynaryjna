from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name="VetPet"),
    path('about/', views.about, name="about"),
    path('signin/', views.signin, name="signin"),
    path('signup/', views.signup, name="signup"),
    path('signout/', views.signout, name="signout"),
    path('activate/<token>/', views.VerificationView, name="activate"),
]
