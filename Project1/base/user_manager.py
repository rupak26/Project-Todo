from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    
    def create_user(self, email, password):
        if not email:
            raise ValueError('User must have an email')
        user = self.create(email=email)
        user.set_password(password)
        user.save()
        return user 