from django.db import models
from django.utils import timezone
from django.contrib.auth.base_user import AbstractBaseUser
from .user_manager import UserManager
# Create your models here.

class User(AbstractBaseUser):
    username = models.CharField(
        verbose_name='username',
        max_length=50,
        blank=True, null=True,unique=True
    )
    email = models.EmailField(max_length=200,unique=True)
    password = models.CharField(max_length=20)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email


class Todo(models.Model):
     title = models.CharField(max_length=100)
     details = models.CharField(max_length=300)
     date = models.DateTimeField(default=timezone.now)

     def __str__(self):
        return self.title
