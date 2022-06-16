import ipaddress
import threading

IPV4_NETMASKS = [int(ipaddress.ip_network(f"0.0.0.0/{i}").netmask) for i in range(32, -1, -1)]

IPV6_NETMASKS = [int(ipaddress.ip_network(f"::/{i}").netmask) for i in range(128, -1, -1)]

NETMASKS_BY_KEY_TYPE = {"ipv4": IPV4_NETMASKS, "ipv6": IPV6_NETMASKS}


def item_to_string(item):
    try:
        ip = ipaddress.ip_network(item)
        return f"ipv{ip.version}_{int(ip.netmask)}_{int(ip.network_address)}"
    except ValueError:
        return f"normal_{item}"


class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache = {}

    def get(self, item):
        with self.lock:
            key = item_to_string(item)
            key_parts = key.split("_")
            key_type = key_parts[0]
            if key_type == "normal":
                return self.cache.get(key)
            item_network_address = int(key_parts[-1])
            netmasks = NETMASKS_BY_KEY_TYPE[key_type]
            for netmask in netmasks:
                resp = self.cache.get(f"{key_type}_{netmask}_{item_network_address & netmask}")
                if resp:
                    return resp

    def get_all(self):
        with self.lock:
            resp = {}
            for item, action in self.cache.items():
                if item.startswith("normal_"):
                    resp[item.split("_", maxsplit=1)[1]] = action
                elif item.startswith("ipv"):
                    _, netmask, address = item.split("_")
                    ip_network = ipaddress.ip_network((int(address), bin(int(netmask)).count("1")))
                    resp[ip_network.__str__()] = action
            return resp

    def insert(self, item, action):
        key = item_to_string(item)
        with self.lock:
            self.cache[key] = action

    def delete(self, item):
        key = item_to_string(item)
        with self.lock:
            self.cache.pop(key, None)

    def __len__(self):
        with self.lock:
            return len(self.cache)


class RedisCache:
    def __init__(self, redis_connection):
        self.lock = threading.Lock()
        self.redis = redis_connection

    def get(self, item):
        with self.lock:
            key = item_to_string(item)
            key_parts = key.split("_")
            key_type = key_parts[0]
            if key_type == "normal":
                return self.redis.hget("pycrowdsec_cache", key)
            item_network_address = int(key_parts[-1])
            netmasks = NETMASKS_BY_KEY_TYPE[key_type]
            check_for = []
            for netmask in netmasks:
                check_for.append(f"{key_type}_{netmask}_{item_network_address & netmask}")
            responses = self.redis.hmget("pycrowdsec_cache", check_for)
            for response in responses:
                if response:
                    return response.decode()

    def insert(self, item, action):
        with self.lock:
            key = item_to_string(item)
            self.redis.hset("pycrowdsec_cache", key, action)

    def get_all(self):
        with self.lock:
            resp = {}
            for item, action in self.redis.hgetall("pycrowdsec_cache").items():
                item, action = item.decode(), action.decode()
                if item.startswith("normal_"):
                    resp[item.split("_", maxsplit=1)[1]] = action
                elif item.startswith("ipv"):
                    _, netmask, address = item.split("_")
                    ip_network = ipaddress.ip_network((int(address), bin(int(netmask)).count("1")))
                    resp[ip_network.__str__()] = action
            return resp

    def delete(self, item):
        with self.lock:
            key = item_to_string(item)
            self.redis.hdel("pycrowdsec_cache", key)

    def __len__(self):
        with self.lock:
            return self.redis.hlen("pycrowdsec_cache")
