from urllib.parse import urlparse
from tld import get_tld
import re
import urllib.request
from urllib.error import HTTPError
from bs4 import BeautifulSoup
from datetime import datetime
import time
import whois
import socket

class ExtractFeatures:
    def __init__(self, url):
        self.url=url
        self.res = get_tld(url, as_object=True)
        self.t = urlparse(url)

    def num_dots(self):
        cdot = 0
        for i in self.url:
            if i == '.':
                cdot = cdot + 1
        return cdot     

    def num_sdomain(self):
        csdomain = 0
        if not self.url:
            csdomain = 0
        else:
            csdomain = len(self.url.split('.'))
        return csdomain

    def url_length(self):
        length = len(self.url)
        return length

    def num_dash(self):
        cdash = 0
        for i in self.url:
            if i == '-':
                cdash = cdash + 1
        return cdash

    def check_at(self):
        if '@' in self.url:
            cat = 1
            return cat
        else:
            cat = 0
            return cat

    def check_til(self):
        if '~' in self.url:
            til = 1
            return til
        else:
            til = 0
            return til

    def num_und(self):
        cund = 0
        for i in self.url:
            if i == '_':
                cund = cund + 1
        return cund

    def num_per(self):
        cper = 0
        for i in self.url:
            if i == '%':
                cper = cper + 1
        return cper

    def num_query(self):
        cquery = 0
        if not self.url:
            cquery = 0
            return cquery
        else:  
            cquery = len(self.url.split('&'))
            return cquery

    def num_and(self):
        cand = 0
        for i in self.url:
            if i == '&':
                cand = cand + 1
        return cand

    def num_hash(self):
        chash = 0
        for i in self.url:
            if i == '#':
                chash = chash + 1
        return chash

    def num_dash_host(self):
        for urls in self.url:
            spltAr = self.url.split("://");
            i = (0,1)[len(spltAr)>1];
            dm = spltAr[i].split("?")[0].split('/')[0].split(':')[0].lower();
        dash = 0
        for i in dm:
            if i == '-':
                dash = dash + 1
        return dash

    def num_numeric_chars(self):
        numbers = sum(c.isdigit() for c in self.url)
        return numbers
    
    def no_https(self):
        if 'https' in self.url:
            return 1
        else:
            return 0
    
    def having_ip_address(self):
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',self.url)     #Ipv6
        if match:
            #print match.group()
            return 1
        else:
            #print 'No matching pattern found'
            return 0

    def domain_in_subdomains(self):
        # res = get_tld(self.url, as_object=True)

        if self.res.tld in self.res.subdomain:
            return 1
        else:
            return 0

    def domain_in_path(self):
        # t = urlparse(self.url)
        # res = get_tld(self.url, as_object=True)

        if self.res.tld in self.t.path:
            return 1
        else:
            return 0

    def length_hostname(self):
        # t = urlparse(self.url)
        return len(self.t.netloc)

    def length_path(self):
        # t = urlparse(self.url)
        return len(self.t.path)

    def length_query(self):
        # t = urlparse(self.url)
        return len(self.t.query)

    def double_slash_in_path(self):
        # t = urlparse(self.url)
        if '//' in self.t.path:
            return 1
        else:
            return 0
    
    def num_sensitive_words(self):
        sensitive=['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'sign-in', 'banking', 'confirm', 'signon', '.exe', '.zip', '.rar', '.jpg', '.gif', 'plugins', 'paypal', 'order', 'payment', 'files']
        if any(word in self.url for word in sensitive):    
            return 1
        else:
            return 0

    
    def shortening_service(self):
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',self.url)
        if match:
            return 1
        else:
            return 0

    def web_traffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
        except TypeError:
            return 1
        except HTTPError:
            return 2
        rank= int(rank)
        if (rank<100000):
            return 0
        else:
            return 2
            
    def check_date(self):
        dns=0
        try:
            domain_name=whois.whois(urlparse(self.url).netloc)
        except:
            dns=1
        if dns==1:
            return 1
        else:
            expiry=domain_name.expiration_date
            today=time.strftime("%Y-%m-%d")
            today=datetime.strptime(today,"%Y-%m-%d")
            if expiry is None:
                return 1
            elif type(expiry) is list or type(today) is list:
                return 2
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                    try:
                        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                    except:
                        return 2
                registration_time=abs((expiration_date-today).days)
                if (registration_time/365)<=1:
                    return 1
                else:
                    return 0


    def check_dns(self):
        dns=0
        try:
            domain_name=whois.whois(urlparse(self.url).netloc)
            #print(domain_name)
        except:
            dns=1
        if dns==1:
            return 1
        else:
            return 0

    def statistical_report(self):
        hostname = self.url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',self.url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)  
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0

a=ExtractFeatures('http://luxuryupgradepro.com/ymailNew/ymailNew/')
print("Shortening service:", a.shortening_service())
# print("Check web traffic:", a.web_traffic())
print("Check Date:", a.check_date())
print("Check DNS:", a.check_dns())
print("Check Statistical report:", a.statistical_report())
