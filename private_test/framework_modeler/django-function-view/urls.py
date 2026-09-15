from django.urls import path

from .views import user_detail


urlpatterns = [
    path("users/<int:user_id>/", user_detail),
]

