from django.urls import path
from .views import UserRegistrationView,userLoginView,TodoView
urlpatterns = [
    path('login/',userLoginView.as_view(),name = 'Login'),
    path('register/',UserRegistrationView.as_view(),name='Registration'),
    path('todos/', TodoView.as_view(), name='todos'),
]