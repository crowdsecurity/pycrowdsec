import ipaddress
from itertools import chain


class Cache:
    def __init__(self, **kwargs):
        self.ip_cache = IPCache()
        self.normal_cache = {}
        self.use_redis = False
        if "redis_connection" in kwargs:
            self.use_redis = True
            self.redis = kwargs["redis_connection"]
            self.load_from_redis()

    def get(self, item):
        try:
            ipaddress.ip_address(item)
            return self.ip_cache.get_action_for(item)
        except ValueError:
            return self.normal_cache.get(item)

    def insert(self, item, action):
        try:
            ip = ipaddress.ip_network(item)
            self.ip_cache.insert(item, action)
            if self.use_redis:
                self.redis.hset(
                    "pycrowdsec_cache",
                    f"ipv{ip.version}_{int(ip.netmask)}_{int(ip.network_address)}",
                    action,
                )

        except ValueError:
            self.normal_cache[item] = action
            if self.use_redis:
                self.redis.hset("pycrowdsec_cache", f"normal_{item}", action)

    def delete(self, item):
        try:
            ip = ipaddress.ip_network(item)
            self.ip_cache.delete(item)
            if self.use_redis:
                self.redis.hdel(
                    "pycrowdsec_cache",
                    f"ipv{ip.version}_{int(ip.netmask)}_{int(ip.network_address)}",
                )
        except ValueError:
            try:
                del self.normal_cache[item]
                if self.use_redis:
                    self.redis.hdel("pycrowdsec_cache", f"normal_{item}")
            except KeyError:
                pass

    def load_from_redis(self):
        for key, value in self.redis.hgetall("pycrowdsec_cache").items():
            key, value = key.decode(), value.decode()
            if key.startswith("normal"):  # normal_CN = "ban"
                key = key.split("_", maxsplit=1)[1]
                self.normal_cache[key] = value
            elif key.startswith("ipv4"):  # normal_0_1.2.3.4 = "captcha"
                key_comps = key.split("_")
                netmask, ip = int(key_comps[1]), int(key_comps[-1])
                self.ip_cache.ipv4_nodes_by_netmask[netmask][ip] = value
            elif key.startswith("ipv6"):
                key_comps = key.split("_")
                netmask, ip = int(key_comps[1]), int(key_comps[-1])
                self.ip_cache.ipv6_nodes_by_netmask[netmask][ip] = value

    def validate_redis_config(self):
        pass

    def __len__(self):
        return len(self.normal_cache) + len(self.ip_cache)

    def __eq__(self, other):
        return self.normal_cache == other.normal_cache and self.ip_cache == other.ip_cache


class IPCache:
    def __init__(self):
        # This "reverse range" comprehension is deliberate. Since dicts are ordered
        # when we iterate on them, we get the "more specific"/smaller network first.
        self.ipv4_nodes_by_netmask = {
            int(ipaddress.ip_network(f"0.0.0.0/{i}").netmask): {} for i in range(32, -1, -1)
        }
        self.ipv6_nodes_by_netmask = {
            int(ipaddress.ip_network(f"::/{i}").netmask): {} for i in range(128, -1, -1)
        }

    def _get_container_for_ip_network(self, ip_network):
        if ip_network.version == 4:
            return self.ipv4_nodes_by_netmask
        return self.ipv6_nodes_by_netmask

    def insert(self, ip_network_string, action):
        ip_network = ipaddress.ip_network(ip_network_string)
        container = self._get_container_for_ip_network(ip_network)
        container[int(ip_network.netmask)][int(ip_network.network_address)] = action

    def delete(self, ip_network_string):
        ip_network = ipaddress.ip_network(ip_network_string)
        container = self._get_container_for_ip_network(ip_network)
        try:
            del container[int(ip_network.netmask)][int(ip_network.network_address)]
        except KeyError:
            pass

    def get_action_for(self, ip_network_string):
        ip_network = ipaddress.ip_network(ip_network_string)
        ip_decimal_repr = int(ip_network.network_address)
        container = self._get_container_for_ip_network(ip_network)
        for netmask, node in container.items():
            if (netmask & ip_decimal_repr) in node:
                return node[netmask & ip_decimal_repr]

    def __len__(self):
        length = 0
        for _, items in chain(
            self.ipv4_nodes_by_netmask.items(), self.ipv6_nodes_by_netmask.items()
        ):
            length += len(items)
        return length

    def __eq__(self, other):
        return (
            self.ipv4_nodes_by_netmask == other.ipv4_nodes_by_netmask
            and self.ipv6_nodes_by_netmask == other.ipv6_nodes_by_netmask
        )
