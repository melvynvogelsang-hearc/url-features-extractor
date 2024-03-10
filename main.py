import ipaddress
import re
import socket
import ssl
import urllib.request
from datetime import date
from urllib.parse import urlparse
import csv

import requests
import whois
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app, origins=["https://melvynvogelsang.ch"])


class FeatureExtraction:
    features = []
    def __init__(self, url):

        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.Https())
        self.features.append(self.AnchorURL())
        self.features.append(self.SubDomains())
        self.features.append(self.prefixSuffix())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.RequestURL())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.AgeofDomain())
        self.features.append(self.UsingIp())
        self.features.append(self.DNSRecording())
        self.features.append(self.longUrl())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.InfoEmail())
        self.features.append(self.symbol())
        self.features.append(self.StatsReport())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.shortUrl())
        self.features.append(self.AbnormalURL())

        self.features.append(self.Favicon())
        self.features.append(self.redirecting())
        self.features.append(self.DomainRegLen())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())

        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.IframeRedirection())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())

    # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            value = -1
            return {"feature": "UsingIP", "value": value, "reason": "L'URL est une adresse IP."}

        except:
            value = 1
            return {"feature": "UsingIP", "value": value, "reason": "L'URL n'est pas une adresse IP."}

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            value = 1
            return {"feature": "LongURL", "value": value,
                    "reason": "L'URL fait " + str(len(self.url)) + " caractères de long."}

        if len(self.url) >= 54 and len(self.url) <= 75:
            value = 0
            return {"feature": "LongURL", "value": value,
                    "reason": "L'URL fait " + str(len(self.url)) + " caractères de long."}

        value = -1
        return {"feature": "LongURL", "value": value,
                "reason": "L'URL fait " + str(len(self.url)) + " caractères de long."}

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          self.url)
        if match:
            value = -1
            return {"feature": "ShortURL", "value": value, "reason": "L'URL est raccourci par un site spécialisé."}

        value = 1
        return {"feature": "ShortURL", "value": value, "reason": "L'URL, n'est pas raccourci par un site spécialisé."}

    # 4.Symbol@
    def symbol(self):
        if re.findall("@", self.url):
            value = -1
            return {"feature": "Symbol@", "value": value, "reason": "Le symbole @ est présent dans l'URL"}

        value = 1
        return {"feature": "Symbol@", "value": value, "reason": "Le symbole @ n'est pas présent dans l'URL"}

    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//') > 6:
            value = -1
            return {"feature": "Redirecting//", "value": value, "reason": "L'URL est utilisé pour une redirection."}

        value = 1
        return {"feature": "Redirecting//", "value": value, "reason": "L'URL n'est pas utilisé pour une redirection."}

    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                value = -1
                return {"feature": "PrefixSuffix-", "value": value, "reason": "L'URL contient un -"}

            value = 1
            return {"feature": "PrefixSuffix-", "value": value, "reason": "L'URL ne contient pas de -"}

        except:
            value = -1
            return {"feature": "PrefixSuffix-", "value": value, "reason": "Exception"}

    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            value = 1
            return {"feature": "SubDomains", "value": value, "reason": "L'URL ne contient pas de sous-domaine."}

        elif dot_count == 2:
            value = 0
            return {"feature": "SubDomains", "value": value, "reason": "L'URL contient un sous-domaine."}

        value = -1
        return {"feature": "SubDomains", "value": value, "reason": "Exception"}

    # 8.HTTPS
    def Https(self):
        try:
            url = self.whois_response.domain
            hostname = url
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print(ssock.getpeercert())
                    if 'issuer' in ssock.getpeercert():
                        value = 1
                        return {"feature": "HTTPS", "value": value, "reason": "Certificat HTTPS valide"}
                    else:
                        if 'https' in urlparse(self.url).scheme:
                            value = 0
                            return {"feature": "HTTPS", "value": value,
                                    "reason": "Faux certificat HTTPS utilisé mais https présent"}
                        else:
                            value = -1
                            return {"feature": "HTTPS", "value": value, "reason": "Faux certificat HTTPS utilisé"}
        except Exception as e:
            value = -1
            return {"feature": "HTTPS", "value": value, "reason": str(e)}

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if (len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if (len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                value = 1
                return {"feature": "DomainRegLen", "value": value,
                        "reason": "Premier enregistrement du domaine il y a " + str(age) + " mois."}

            value = -1
            return {"feature": "DomainRegLen", "value": value,
                    "reason": "Premier enregistrement du domaine il y a " + str(age) + " mois."}

        except Exception as e:
            value = -1
            return {"feature": "DomainRegLen", "value": value, "reason": str(e)}

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        value = 1
                        return {"feature": "Favicon", "value": value, "reason": "Favicon trouvé."}

            value = -1
            return {"feature": "Favicon", "value": value, "reason": "Favicon non trouvé."}

        except Exception as e:
            value = -1
            return {"feature": "Favicon", "value": value, "reason": str(e)}

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                value = -1
                return {"feature": "NonStdPort", "value": value, "reason": "Port utilisé dans l'URL."}

            value = 1
            return {"feature": "NonStdPort", "value": value, "reason": "Port non utilisé dans l'URL."}

        except Exception as e:
            value = -1
            return {"feature": "NonStdPort", "value": value, "reason": str(e)}

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            parsed_url = urlparse(self.url)

            if 'https' in parsed_url.scheme:
                value = -1
                return {"feature": "HTTPSDomainURL", "value": value, "reason": "HTTPS utilisé"}

            value = 1
            return {"feature": "HTTPSDomainURL", "value": value, "reason": "HTTPS non utilisé"}

        except Exception as e:
            value = -1
            return {"feature": "HTTPSDomainURL", "value": value, "reason": str(e)}

    # 13. RequestURL
    def RequestURL(self):
        try:
            # correction variable non assignée
            i = 0
            success = 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url.lower() in img['src'].lower() or self.domain.lower() in img['src'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url.lower() in audio['src'].lower() or self.domain.lower() in audio['src'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url.lower() in embed['src'].lower() or self.domain.lower() in embed['src'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url.lower() in iframe['src'].lower() or self.domain.lower() in iframe['src'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                if i != 0:
                    percentage = success / float(i) * 100
                else:
                    percentage = 0

                if percentage < 22.0:
                    value = 1
                    return {"feature": "RequestURL", "value": value,
                            "reason": str(percentage) + "% des médias contienent l'URL."}

                elif ((percentage >= 22.0) and (percentage < 61.0)):
                    value = 0
                    return {"feature": "RequestURL", "value": value,
                            "reason": str(percentage) + "% des médias contienent l'URL."}

                else:
                    value = -1
                    return {"feature": "RequestURL", "value": value,
                            "reason": str(percentage) + "% des médias contienent l'URL."}

            except Exception as e:
                value = 0
                return {"feature": "RequestURL", "value": value, "reason": "Exception"}

        except Exception as e:
            value = -1
            return {"feature": "RequestURL", "value": value, "reason": "Exception"}

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            # Ne pas inclure les link dans le head
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'].lower() or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url.lower() in a['href'].lower() or self.domain.lower() in a['href'].lower()):
                    unsafe = unsafe + 1
                i = i + 1
            try:
                if unsafe != 0 and i != 0:
                    percentage = unsafe / float(i) * 100
                else:
                    percentage = 0

                if percentage < 31.0:
                    value = 1
                    return {"feature": "AnchorURL", "value": value,"reason": str(percentage) + "% des liens ne sont pas sécurisés", "whois": self.whois_response}
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    value = 0
                    return {"feature": "AnchorURL", "value": value,"reason": str(percentage) + "% des liens ne sont pas sécurisés", "whois": self.whois_response}

                else:
                    value = -1
                    return {"feature": "AnchorURL", "value": value,"reason": str(percentage) + "% des liens ne sont pas sécurisés", "whois": self.whois_response}

            except Exception as ee:
                value = -1
                return {"feature": "AnchorURL", "value": value, "reason": str(ee)}
        except Exception as e:
            value = -1
            return {"feature": "AnchorURL", "value": value, "reason": str(e)}

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0

            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'].lower())]
                if self.url.lower() in link['href'].lower() or self.domain.lower() in link['href'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'].lower())]
                if self.url.lower() in script['src'].lower() or self.domain.lower() in script['src'].lower() or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                if i != 0:
                    percentage = success / float(i) * 100
                else:
                    percentage = 0

                if percentage < 17.0:
                    value = 1
                    return {"feature": "LinksInScriptTags", "value": value,
                            "reason": str(percentage) + "% des liens dans script et link contiennent l'URL."}
                elif ((percentage >= 17.0) and (percentage < 81.0)):
                    value = 0
                    return {"feature": "LinksInScriptTags", "value": value,
                            "reason": str(percentage) + "% des liens dans script et link contiennent l'URL."}

                else:
                    value = -1
                    return {"feature": "LinksInScriptTags", "value": value,
                            "reason": str(percentage) + "% des liens dans script et link contiennent l'URL."}

            except Exception as e:
                value = 0
                return {"feature": "LinksInScriptTags", "value": value, "reason": str(e)}

        except Exception as e:
            value = -1
            return {"feature": "LinksInScriptTags", "value": value, "reason": str(e)}

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                value = 1
                return {"feature": "ServerFormHandler", "value": value,
                        "reason": "Aucun formulaire trouvé dans la page."}

            else:
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        value = -1
                        return {"feature": "ServerFormHandler", "value": value,
                                "reason": "Balise action vide ou about:blank."}

                    elif self.url not in form['action'] and self.domain not in form['action']:
                        value = 0
                        return {"feature": "ServerFormHandler", "value": value,
                                "reason": "Le domaine ou l'URL ne se trouve pas dans la balise action."}

                    else:
                        value = 1
                        return {"feature": "ServerFormHandler", "value": value, "reason": "Autre."}

        except Exception as e:
            value = -1
            return {"feature": "ServerFormHandler", "value": value, "reason": str(e)}

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            # Correction de l'expression régulière
            if re.findall(r"mail\(\)|mailto:[\w\.-]+@[\w\.-]+\.\w+(?:\?\w+=\w+(&\w+=\w+)*)?", self.response.text):
                value = -1
                return {"feature": "InfoEmail", "value": value, "reason": "Mailto trouvé dans la page."}

            else:
                value = 1
                return {"feature": "InfoEmail", "value": value, "reason": "Mailto non trouvé dans la page."}

        except Exception as e:
            value = -1
            return {"feature": "InfoEmail", "value": value, "reason": str(e)}

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if isinstance(self.whois_response.domain_name, list):
                for dn in self.whois_response.domain_name:
                    if dn.lower() in self.url.lower():
                        value = 1
                        return {"feature": "AbnormalURL", "value": value, "reason": "Nom de domaine présent dans l'URl"}
                    else:
                        value = -1
                        return {"feature": "AbnormalURL", "value": value,
                                "reason": "Nom de domaine non présent dans l'URl"}
            else:
                if self.whois_response.domain_name.lower() in self.url.lower():
                    value = 1
                    return {"feature": "AbnormalURL", "value": value, "reason": "Nom de domaine présent dans l'URl"}
                else:
                    value = -1
                    return {"feature": "AbnormalURL", "value": value, "reason": "Nom de domaine non présent dans l'URl"}
        except Exception as e:
            value = -1
            return {"feature": "AbnormalURL", "value": value, "reason": str(e)}

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                value = 1
                return {"feature": "WebsiteForwarding", "value": value,
                        "reason": str(len(self.response.history)) + " redirections trouvées."}

            elif len(self.response.history) <= 4:
                value = 0
                return {"feature": "WebsiteForwarding", "value": value,
                        "reason": str(len(self.response.history)) + " redirections trouvées."}

            else:
                value = -1
                return {"feature": "WebsiteForwarding", "value": value,
                        "reason": str(len(self.response.history)) + " redirections trouvées."}

        except Exception as e:
            value = -1
            return {"feature": "WebsiteForwarding", "value": value, "reason": str(e)}

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                value = 1
                return {"feature": "StatusBarCust", "value": value, "reason": "OnMouseOver trouvée sur la page."}

            else:
                value = -1
                return {"feature": "StatusBarCust", "value": value, "reason": "OnMouseOver non trouvée sur la page."}

        except Exception as e:
            value = -1
            return {"feature": "StatusBarCust", "value": value, "reason": str(e)}

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                value = 1
                return {"feature": "DisableRightClick", "value": value, "reason": "Clic droit désactivé sur la page."}

            else:
                value = -1
                return {"feature": "DisableRightClick", "value": value,
                        "reason": "Clic droit non désactivé sur la page."}

        except Exception as e:
            value = -1
            return {"feature": "DisableRightClick", "value": value, "reason": str(e)}

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                value = 1
                return {"feature": "UsingPopupWindow", "value": value, "reason": "Balise alert() trouvée dans la page."}

            else:
                value = -1
                return {"feature": "UsingPopupWindow", "value": value,
                        "reason": "Aucune balise alert() trouvée dans la page."}

        except Exception as e:
            value = -1
            return {"feature": "UsingPopupWindow", "value": value, "reason": str(e)}

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                value = 1
                return {"feature": "IframeRedirection", "value": value, "reason": "iFrame trouvée dans la page."}
            else:
                value = -1
                return {"feature": "IframeRedirection", "value": value, "reason": "Aucune iFrame trouvée dans la page."}
        except Exception as e:
            value = -1
            return {"feature": "IframeRedirection", "value": value, "reason": str(e)}

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if (len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            # Plus grand que 6 mois
            if age >= 6:
                value = 1
                return {"feature": "AgeofDomain", "value": value,
                        "reason": "Date du domaine est de " + str(age) + " mois."}
            else:
                value = -1
                return {"feature": "AgeofDomain", "value": value,
                        "reason": "Date du domaine est de " + str(age) + " mois."}
        except Exception as e:
            value = -1
            return {"feature": "AgeofDomain", "value": value, "reason": str(e)}

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if (len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                value = 1
                return {"feature": "DNSRecording", "value": value,
                        "reason": "Date du premier enregistrement DNS est de " + str(age) + " mois."}
            else:
                value = -1
                return {"feature": "DNSRecording", "value": value,
                        "reason": "Date du premier enregistrement DNS est de " + str(age) + " mois."}
        except Exception as e:
            value = -1
            return {"feature": "DNSRecording", "value": value, "reason": str(e)}

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = \
            BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(),
                          "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                value = 1
                return {"feature": "WebsiteTraffic", "value": value}
            else:
                value = 0
                return {"feature": "WebsiteTraffic", "value": value}
        except Exception as e:
            value = -1
            return {"feature": "WebsiteTraffic", "value": value}

    # 27. PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                value = 1
                return {"feature": "PageRank", "value": value}
            else:
                value = -1
                return {"feature": "PageRank", "value": value}
        except:
            value = -1
            return {"feature": "PageRank", "value": value}

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                value = 1
                return {"feature": "LinksPointingToPage", "value": value,
                        "reason": "Aucun lien entrant sur la page trouvé."}
            elif number_of_links <= 2:
                value = 0
                return {"feature": "LinksPointingToPage", "value": value,
                        "reason": str(number_of_links) + " liens entrants trouvés."}
            else:
                value = -1
                return {"feature": "LinksPointingToPage", "value": value,
                        "reason": str(number_of_links) + " liens entrants trouvés."}
        except Exception as e:
            value = -1
            return {"feature": "LinksPointingToPage", "value": value, "reason": str(e)}

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address)
            if url_match:
                value = -1
                return {"feature": "StatsReport", "value": value, "reason": "Extension de l'URL suspicieuse."}
            elif ip_match:
                value = -1
                return {"feature": "StatsReport", "value": value, "reason": "Adresse IP du site suspicieuse."}
            else:
                value = 1
                return {"feature": "StatsReport", "value": value, "reason": "L'adresse IP et l'URL sont corrects."}

        except Exception as e:
            value = 1
            tuple = {"feature": "StatsReport", "value": value, "reason": str(e)}
            return tuple

    def addToCSV(self, features_top_20):
        file = 'custom_urls.csv'
        features = []
        for f in self.features:
            if f['feature'] in features_top_20:
                features.append(f['value'])
        return features
        #with open(file, mode='a', newline='', encoding='utf-8') as csvFile:
         #   writer = csv.writer(csvFile)
          #  writer.writerow(features)


    def getFeaturesList(self):
        features_list = []  # Initialiser une liste pour stocker les caractéristiques filtrées
        features_top_20 = ["HTTPS", "AnchorURL", "SubDomains", "PrefixSuffix-", "LinksInScriptTags", "RequestURL", "LinksPointingToPage", "DomainRegLen", "ServerFormHandler", "AgeofDomain", "UsingIP", "DNSRecording", "LongURL", "UsingPopupWindow", "InfoEmail", "Symbol@", "StatsReport", "WebsiteForwarding", "ShortURL", "AbnormalURL"]

        for f in self.features:
            if f['feature'] in features_top_20:
                # Créer un dictionnaire pour la caractéristique actuelle en incluant 'name', 'value', et 'reason'
                obj = {
                    'name': f['feature'],
                    'value': f['value'],
                    'reason': f['reason']
                }
                features_list.append(obj)  # Ajouter le dictionnaire à la liste des caractéristiques

        forCSV = self.addToCSV(features_top_20)
        # Retourner le résultat final dans le format JSON attendu
        print(features_list)
        return {'features': features_list, "forCSV": forCSV}


def query(url):
    obj = FeatureExtraction(url)
    return obj.getFeaturesList()


@app.route('/get-features', methods=['POST'])
@cross_origin(origin='melvynvogelsang.ch')
def get_features():
    url = request.form.get('url')
    response = query(url)
    return jsonify(response)


@app.route('/', methods=['GET'])
def get_root():
    return jsonify({'data': 'Bienvenue sur notre projet BI!'})


if __name__ == '__main__':
    app.run(debug=True)
