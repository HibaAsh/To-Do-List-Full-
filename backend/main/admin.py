from django.contrib import admin
from .models import Task, User

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ("name_en", "name_ar", "user")

admin.site.register(User)


