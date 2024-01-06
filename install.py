import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Liste des packages requis
packages = [
    "ipaddress",
    "beautifulsoup4",  # BeautifulSoup est dans le package beautifulsoup4
    "requests",
    "python-whois",    # le package pour whois est python-whois
    "python-dateutil", # le package pour dateutil.parser est python-dateutil
    "google"           # Assurez-vous que c'est le package Google dont vous avez besoin
]



if __name__ == '__main__':
    for package in packages:
        install(package)
    print("Tous les packages requis ont été installés.")


