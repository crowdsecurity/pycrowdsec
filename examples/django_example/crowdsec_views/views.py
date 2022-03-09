import os

import requests
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.http.response import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

# Create your views here.


def validate_captcha_resp(g_recaptcha_response):
    resp = requests.post(
        url="https://www.google.com/recaptcha/api/siteverify",
        data={
            "secret": os.environ.get("GOOGLE_RECAPTCHA_PRIVATE_KEY"),
            "response": g_recaptcha_response,
        },
    ).json()
    return resp["success"]


def captcha_view(request):
    if not cache.get("valid_captcha_keys"):
        cache.set("valid_captcha_keys", set(), 30)

    if request.method == "GET":
        return render(
            request,
            "captcha_page.html",
            context={"public_key": os.environ.get("GOOGLE_RECAPTCHA_SITE_KEY")},
        )

    elif request.method == "POST":
        captcha_resp = request.POST.get("g-recaptcha-response")
        if not captcha_resp:
            return redirect(reverse("captcha_view"))

        is_valid = validate_captcha_resp(captcha_resp)
        if is_valid:
            valid_keys = cache.get("valid_captcha_keys")
            valid_keys.add(captcha_resp)
            cache.set("valid_captcha_keys", valid_keys, 30)
            request.session["captcha_key"] = captcha_resp
            return redirect(reverse("index"))
        else:
            return redirect(reverse("captcha_view"))


def ban_view(request):
    raise PermissionDenied


def index_view(request):
    return HttpResponse("<h1> Hello  ! </h1>")
