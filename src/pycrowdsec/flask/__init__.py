from flask import request


def get_crowdsec_middleware(
    actions_by_name,
    crowdsec_cache,
    ip_transformers=[lambda request: request.remote_addr],
    exclude_views=(),
):
    """
    Returns a middleware function for flask, which can be registered by passsing it to app.before_request

        Parameters
        ----------
            actions_by_name(Required):
                Dictionary where key is an action string, eg "ban". The value is a function which carries out the action.
                Eg {"ban": lambda : redirect(url_for("ban_page")) }

            crowdsec_cache(Required):
                An instance of pycrowdsec.cache.Cache.
                It is a KV store, keys being entities like IP, Country strings etc.
                Values are action string for these entities. Eg {"1.2.3.4": "ban"}

            ip_transformers(Optional):
                List of functions which take in the request and produce some other string.
                This produced string is looked up in the cache, if found then then the remediation
                is applied.
                Eg: [lambda ip: ip, lambda ip: get_country_code_for(ip)]

            exclude_views(Optional):
                List of view function names, to exclude crowdsec actions.
                Example: ["ban_view", "captcha_page", "contact_page"]
    """

    def middleware():
        for ip_transformer in ip_transformers:
            action_name = crowdsec_cache.get(ip_transformer(request))
            if not action_name:
                return

            destination_view = request.url_rule.endpoint
            if destination_view in exclude_views:
                return
            if action_name in actions_by_name:
                return actions_by_name[action_name]()

    return middleware
