"""django_example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from os import name

from crowdsec_views.views import ban_view, captcha_view, index_view
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("", index_view, name="index"),
    path("admin/", admin.site.urls),
    path("ban/", view=ban_view, name="ban_view"),
    path("captcha/", view=captcha_view, name="captcha_view"),
]
