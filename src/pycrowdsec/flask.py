from flask import request


def get_crowdsec_middleware(
    actions_by_name, crowdsec_cache, ip_transformers=[lambda ip: ip], exclude_views=[]
):
    def middleware():
        for ip_transformer in ip_transformers:
            action_name = crowdsec_cache.get(ip_transformer(request.remote_addr))
            if not action_name:
                return

            destination_view = request.url_rule.endpoint
            if destination_view in exclude_views:
                return

            if action_name in actions_by_name:
                return actions_by_name[action_name](destination_view)

    return middleware
