from django.urls import path, include
from .views import TaskViewSet, RegisterAPI, LoginAPI, LogoutAPI, UserViewSet
from rest_framework.routers import SimpleRouter

task_router = SimpleRouter()
task_router.register('', TaskViewSet, basename="TaskViewSet")

user_router = SimpleRouter()
user_router.register('', UserViewSet, basename="UserViewSet")

urlpatterns = [
    path("task/", include(task_router.urls)),
    path("user/", include(user_router.urls)),
    path('register/', RegisterAPI.as_view(), name='register'),
    path('login/', LoginAPI.as_view(), name='login'),
    path('logout/', LogoutAPI.as_view(), name='logout'),
]