def get_geoip_looker(db_path, scope="city"):

    import geoip2.database
    from geoip2.errors import AddressNotFoundError

    reader = geoip2.database.Reader(db_path)

    def geoip_looker(ip):
        try:
            scope_looker = getattr(reader, scope)
            return scope_looker(ip)
        except AttributeError:
            raise AttributeError(f"The mmdb at {db_path} doesn't support {scope} ")

        except AddressNotFoundError:
            return None

    return geoip_looker
