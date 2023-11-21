# Generated by Django 4.2.6 on 2023-11-21 11:57

from django.conf import settings
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "first_name",
                    models.CharField(
                        blank=True, max_length=150, verbose_name="first name"
                    ),
                ),
                (
                    "last_name",
                    models.CharField(
                        blank=True, max_length=150, verbose_name="last name"
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(
                        default=django.utils.timezone.now, verbose_name="date joined"
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                (
                    "username",
                    models.CharField(
                        error_messages={
                            "unique": "A user with that username already exists."
                        },
                        max_length=30,
                        unique=True,
                        validators=[
                            django.contrib.auth.validators.UnicodeUsernameValidator()
                        ],
                        verbose_name="username",
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        max_length=255, unique=True, verbose_name="email address"
                    ),
                ),
                (
                    "photo",
                    models.ImageField(blank=True, null=True, upload_to="user_profile/"),
                ),
                (
                    "first_name_en",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=50,
                        verbose_name="First name in English",
                    ),
                ),
                (
                    "last_name_en",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=50,
                        verbose_name="Last name in English",
                    ),
                ),
                (
                    "first_name_ar",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=50,
                        verbose_name="First name in Arabic",
                    ),
                ),
                (
                    "last_name_ar",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=50,
                        verbose_name="Last name in Arabic",
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False, null=True)),
                ("is_superuser", models.BooleanField(default=False, null=True)),
                (
                    "profile_image",
                    models.ImageField(
                        default="profile_images/profile.jpg",
                        upload_to="profile_images/",
                    ),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "ordering": ["-date_joined"],
            },
        ),
        migrations.CreateModel(
            name="Task",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name_en", models.CharField(max_length=20)),
                ("name_ar", models.CharField(max_length=20)),
                ("description_en", models.TextField()),
                ("description_ar", models.TextField()),
                ("important", models.BooleanField(default=False)),
                ("completed", models.BooleanField(default=False)),
                ("due_to_date", models.DateField()),
                ("due_to_time", models.TimeField()),
                (
                    "read_by_me",
                    models.BooleanField(blank=True, default=False, null=True),
                ),
                ("read_by_admin", models.BooleanField(default=False)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="users",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]