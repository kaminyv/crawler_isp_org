import socket
from cymruwhois import Client

DOMAINS = [
    'google.com',
    'facebook.com',
    'youtube.com',
    'twitter.com',
    'instagram.com',
    'linkedin.com',
    'apple.com',
    'microsoft.com',
    'wikipedia.org',
    'wordpress.org',
    'googletagmanager.com',
]


class Crawler(Client):
    @staticmethod
    def __lookup_ip_by_domain(domain: str) -> str:
        try:
            ip = socket.gethostbyname(domain)
        except socket.herror:
            ip = 'Not rezolve'
        return ip

    @staticmethod
    def __lookup_hostname_by_ip(ip: str) -> str:
        try:
            host_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            host_name = 'Not rezolve'
        return host_name

    def lookup_domain_info(self, domains: list) -> list:
        """
        Returns a list of items with information about ip/asn/org records for domains
        :param domains: A list type containing one or more domains.
        :return:
        """
        domains_list = list()
        for domain in domains:
            ip = self.__lookup_ip_by_domain(domain)
            hostname = self.__lookup_hostname_by_ip(ip)
            domains_list.append({
                'domain': domain,
                'ip': ip,
                'org': hostname,
            })

        asn_domain = self.lookupmany_dict([item['ip'] for item in domains_list if item['ip'] != 'Not rezolve'])

        domain_info = domains_list.copy()

        for item in domain_info:
            for asn in asn_domain:
                if item['ip'] == asn:
                    item['asn'] = asn_domain[asn].asn
                    item['cc'] = asn_domain[asn].cc
                    item['key'] = asn_domain[asn].key
                    item['owner'] = asn_domain[asn].owner
                    item['prefix'] = asn_domain[asn].prefix

        return domain_info


if __name__ == '__main__':
    print(Crawler().lookup_domain_info(DOMAINS))
