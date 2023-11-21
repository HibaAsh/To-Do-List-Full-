from django.db import models
from django.contrib.auth.models import (
    AbstractUser, BaseUserManager
)
from django.utils.translation import gettext_lazy as _
from datetime import date

import uuid
from rest_framework import permissions
from rest_framework_simplejwt.tokens import RefreshToken
import os

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not username:
            raise ValueError('Users must have an username')
        
        user = self.model(
            username=username,
            password=password,
            email=self.normalize_email(email),
            **extra_fields,

        )
        user.set_password(password)
        # user.active = is_active
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        # if extra_fields.get('is_staff') is not True:
        #     raise ValueError(_('Superuser must have is_staff=True.'))
        # if extra_fields.get('is_superuser') is not True:
        #     raise ValueError(_('Superuser must have is_superuser=True.'))
        
        user = self.create_user(
            username=username,
            email=email,
            password=password,
            **extra_fields,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractUser):

    uuid = models.UUIDField(primary_key=False, unique=True, default=uuid.uuid4, editable=False)
    username = models.CharField(_('username'),
        max_length=30,
        unique=True,
        validators=[AbstractUser.username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
 
    email = models.EmailField(_('email address'), max_length=255, unique=True)
    photo = models.ImageField(upload_to='user_profile/', blank=True, null=True)

    first_name_en = models.CharField(_('First name in English'), max_length=50, default="", blank=True)
    last_name_en = models.CharField(_('Last name in English'), max_length=50, default="", blank=True)
    
    first_name_ar = models.CharField(_('First name in Arabic'), max_length=50, default="", blank=True)
    last_name_ar = models.CharField(_('Last name in Arabic'), max_length=50, default="", blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False, null=True) # a admin user; non super-user
    is_superuser = models.BooleanField(default=False, null=True) # a superuser

    profile_image = models.ImageField(upload_to= 'profile_images/', default='profile_images/profile.jpg') 

    lookup_field = 'username'

    objects = UserManager()

    class Meta:
        ordering = ['-date_joined']


    # model methods 
    def __str__(self):
        return self.username
    
    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return  {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    

class Task(models.Model):
    name_en = models.CharField(max_length=20)
    name_ar = models.CharField(max_length=20)

    description_en = models.TextField()
    description_ar = models.TextField()

    important = models.BooleanField(default=False)
    completed = models.BooleanField(default=False)

    due_to_date = models.DateField()
    due_to_time = models.TimeField()

    read_by_me = models.BooleanField(null=True, blank=True, default=False)
    read_by_admin = models.BooleanField(default=False)

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='users')

    def __str__(self):
        return self.name_en
