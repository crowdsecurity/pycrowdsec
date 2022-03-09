from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.urls import resolve

from pycrowdsec.client import StreamClient


def crowdsec_middleware(get_response):
    def set_settings():
        if not getattr(settings, "PYCROWDSEC_LAPI_KEY"):
            raise Exception("PYCROWDSEC_LAPI_KEY is required")

        settings.pycrowdsec_lapi_url = getattr(
            settings, "PYCROWDSEC_LAPI_URL", "http://localhost:8080/"
        )
        settings.pycrowdsec_user_agent = getattr(
            settings, "PYCROWDSEC_USER_AGENT", "pycrowdsec-django-v1"
        )  # TBD
        settings.pycrowdsec_poll_interval = getattr(settings, "PYCROWDSEC_POLL_INTERVAL", 15)
        settings.pycrowdsec_scopes = getattr(settings, "PYCROWDSEC_SCOPES", ["ip", "range"])
        settings.pycrowdsec_request_transformers = getattr(
            settings,
            "PYCROWDSEC_REQUEST_TRANSFORMERS",
            [lambda request: request.META.get("REMOTE_ADDR")],
        )
        settings.pycrowdsec_actions = getattr(
            settings, "PYCROWDSEC_ACTIONS", {"ban": default_ban_action}
        )

        settings.pycrowdsec_exclude_views = getattr(settings, "PYCROWDSEC_EXCLUDE_VIEWS", set())

    set_settings()
    client = StreamClient(
        api_key=settings.PYCROWDSEC_LAPI_KEY,
        interval=settings.pycrowdsec_poll_interval,
        lapi_url=settings.pycrowdsec_lapi_url,
        scopes=settings.pycrowdsec_scopes,
        user_agent=settings.pycrowdsec_user_agent,
    )

    client.run()

    def middleware(request):
        try:
            if resolve(request.path).view_name in settings.pycrowdsec_exclude_views:
                return get_response(request)
        except:
            return get_response(request)

        for request_transformer in settings.pycrowdsec_request_transformers:
            val = request_transformer(request)
            action = client.get_action_for(val)
            response = get_response(request)
            if action not in settings.pycrowdsec_actions:
                return response
            res = settings.pycrowdsec_actions[action](request)
            if not res:
                return response
            return res

    return middleware


def default_ban_action(request):
    raise PermissionDenied
