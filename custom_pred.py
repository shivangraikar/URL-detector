
from features import ExtractFeatures
import numpy as np
import pandas as pd
import pickle

# =============================================================================
# You can paste your own URLs to predict or you can use the dataset data.csv
# =============================================================================

arr=np.array(['github.com/shivangraikar'])

#https://www.phishtank.com/
# =============================================================================
# x=arr['url'][:50]
# =============================================================================

#arr=pd.read_csv('dataset/his.csv')
#arr=arr['url']
numdots = []
numdom = []
length = []
numdash = []
checkat = []
checktil = []
numund = []
numper = []
numand = []
numhash = []
numdashost = []
numqc = []
nhttps = []
having_ip = []
domain = []
lenh = []
lenpath = []
len_query = []
dss = []
sen_words = []
tiny_url = []
checkdate = []
dns_record = []
statistical_report = []
web_traffic = []


a = ExtractFeatures(url = 'https://github.com/shivangraikar')

for url in arr:
    print(url)
    numdots.append(a.num_dots())
    numdom.append(a.num_sdomain())
    length.append(a.url_length())
    numdash.append(a.num_dash())
    checkat.append(a.check_at())
    checktil.append(a.check_til())
    numund.append(a.num_und())
    numper.append(a.num_per())
    numand.append(a.num_and())
    numhash.append(a.num_hash())
    numdashost.append(a.num_dash_host())
    numqc.append(a.num_numeric_chars())
    nhttps.append(a.no_https())
    having_ip.append(a.having_ip_address())
    domain.append(a.domain_in_subdomains())
    lenh.append(a.length_hostname())
    lenpath.append(a.length_path())
    len_query.append(a.length_query())
    dss.append(a.double_slash_in_path())
    sen_words.append(a.num_sensitive_words())
    tiny_url.append(a.shortening_service())
    checkdate.append(a.check_date())
    dns_record.append(a.check_dns())
    statistical_report.append(a.statistical_report())
    web_traffic.append(a.web_traffic())
    
d={'Dots count':pd.Series(numdots),'Domain count':pd.Series(numdom) ,
    'URL length':pd.Series(length),'Dash count':pd.Series(numdash),
    '@':pd.Series(checkat),'~':pd.Series(checktil),
    '_ count':pd.Series(numund),'Percent count':pd.Series(numper),
    '& count':pd.Series(numand),
    'Hash count':pd.Series(numhash), 'Dash in Host':pd.Series(numdashost),
    'Numchar count':pd.Series(numqc), 'Https count':pd.Series(nhttps),
    'IP':pd.Series(having_ip), 'Domain':pd.Series(domain),
    'Host length':pd.Series(lenh), 'Path length':pd.Series(lenpath),
    'Query length':pd.Series(len_query),
    'Double slash count':pd.Series(dss),
    'Sensitive words':pd.Series(sen_words),
    'tiny_url':pd.Series(tiny_url),
    'Check date':pd.Series(checkdate),
    'DNS record':pd.Series(dns_record),
    'statistical_report':pd.Series(statistical_report),
    'Web traffic':pd.Series(web_traffic)}

finaldata=pd.DataFrame(d)


abc=finaldata.iloc[:,:].values

file= 'svcmodel.pkl'
with open(file,'rb') as f:
    classifier=pickle.load(f)
f.close()

x_pred=classifier.predict(abc)
print(x_pred)


