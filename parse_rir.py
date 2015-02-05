#!/usr/bin/env python
__author__  = "616e6f6e796d6f"

"""
This python script will give you the full list of ip-ranges for a country.
You only have to input the 2 or 3 letter country code, or the beginning of the country name.
The optional whois function will use RWS by default.
"""

import argparse
import math
from urllib import FancyURLopener
from json import dumps
from datetime import datetime
from collections import OrderedDict

from netaddr import IPNetwork
from ipwhois import IPWhois, WhoisLookupError


parser = argparse.ArgumentParser(description="Lookup IP ranges for Country")
parser.add_argument('country', help='The country you wish to lookup (e.g. NL, NLD, NETHER or NETHERLANDS)')
parser.add_argument("-w", "--whois", help="return WHOIS name and description for subnet", action="store_true")
parser.add_argument("-v", "--verbose", help="return WHOIS information for subnet", action="store_true")
parser.add_argument("-nr", "--norws", help="fallback to whois(tcp_43) protocol", action="store_true")
parser.add_argument("-oj", "--outputjson", help="output to json format", action="store_true")
parser.add_argument("-oc", "--outputcsv", help="output to csv format", action="store_true")

args = (parser.parse_args())
country = args.country.upper()

opener = FancyURLopener()
registrars = {"ARIN":"ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	          "RIPE":"ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest",
 	          "AFRINIC":"ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
	          "APNIC":"ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest",
	          "LACNIC":"ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest"}



ipranges = []

def clookup(country):
	arin = [['ANGUILLA','AI','AIA'], ['ANTARCTICA','AQ','ATA'], ['ANTIGUA AND BARBUDA','AG','ATG'], 
		['BAHAMAS','BS','BHS'], ['BARBADOS','BB','BRB'], ['BERMUDA','BM','BMU'], ['BOUVET ISLAND','BV','BVT'], 
		['CANADA','CA','CAN'], ['CAYMAN ISLANDS','KY','CYM'], ['DOMINICA','DM','DMA'], ['GRENADA','GD','GRD'], 
		['GUADELOUPE','GP','GLP'], ['HEARD AND MC DONALD ISLANDS','HM','HMD'], ['JAMAICA','JM','JAM'], 
		['MALAWI','MW','MWI'], ['MARTINIQUE','MQ','MTQ'], ['MONTSERRAT','MS','MSR'], ['PUERTO RICO','PR','PRI'], 
		['SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA','SH','SHN'], ['SAINT BARTH\xc3\x89LEMY','BL','BLM'], 
		['SAINT KITTS AND NEVIS','KN','KNA'], ['SAINT LUCIA','LC','LCA'], ['SAINT PIERRE AND MIQUELON','PM','SPM'], 
		['SAINT VINCENT AND THE GRENADINES','VC','VCT'], ['TURKS AND CAICOS ISLANDS','TC','TCA'], 
		['UNITED STATES OF AMERICA','US','USA'], ['UNITED STATES MINOR OUTLYING ISLANDS','UM','UMI'], 
		['VIRGIN ISLANDS (BRITISH)','VG','VGB'], ['VIRGIN ISLANDS (U.S.)','VI','VIR']]

	ripe = [['ALAND ISLANDS','AX','ALA'], ['ALBANIA','AL','ALB'], ['ANDORRA','AD','AND'], ['ARMENIA','AM','ARM'], 
		['AUSTRIA','AT','AUT'], ['AZERBAIJAN','AZ','AZE'], ['BAHRAIN','BH','BHR'], ['BELARUS','BY','BLR'], 
		['BELGIUM','BE','BEL'], ['BOSNIA AND HERZEGOWINA','BA','BIH'], ['BULGARIA','BG','BGR'], 
		['CROATIA (local name: Hrvatska)','HR','HRV'], ['CYPRUS','CY','CYP'], ['CZECH REPUBLIC','CZ','CZE'], 
		['DENMARK','DK','DNK'], ['ESTONIA','EE','EST'], ['FAROE ISLANDS','FO','FRO'], ['FINLAND','FI','FIN'], 
		['FRANCE','FR','FRA'], ['GEORGIA','GE','GEO'], ['GERMANY','DE','DEU'], ['GIBRALTAR','GI','GIB'], 
		['GREECE','GR','GRC'], ['GREENLAND','GL','GRL'], ['GUERNSEY','GG','GGY'], 
		['HOLY SEE (VATICAN CITY STATE)','VA','VAT'], ['HUNGARY','HU','HUN'], ['ICELAND','IS','ISL'], 
		['IRAN (ISLAMIC REPUBLIC OF)','IR','IRN'], ['IRAQ','IQ','IRQ'], ['IRELAND','IE','IRL'], 
		['ISLE OF MAN','IM','IMN'], ['ISRAEL','IL','ISR'], ['ITALY','IT','ITA'], ['JERSEY','JE','JEY'], 
		['JORDAN','JO','JOR'], ['KAZAKHSTAN','KZ','KAZ'], ['KUWAIT','KW','KWT'], ['KYRGYZSTAN','KG','KGZ'], 
		['LATVIA','LV','LVA'], ['LEBANON','LB','LBN'], ['LIECHTENSTEIN','LI','LIE'], ['LITHUANIA','LT','LTU'], 
		['LUXEMBOURG','LU','LUX'], ['MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF','MK','MKD'], ['MALTA','MT','MLT'], 
		['MOLDOVA, REPUBLIC OF','MD','MDA'], ['MONACO','MC','MCO'], ['MONTENEGRO','ME','MNE'],
        ['NETHERLANDS','NL','NLD'], ['NORWAY','NO','NOR'], ['OMAN','OM','OMN'],
        ['PALESTINIAN TERRITORY, OCCUPIED','PS','PSE'], ['POLAND','PL','POL'], ['PORTUGAL','PT','PRT'],
        ['QATAR','QA','QAT'], ['ROMANIA','RO','ROU'], ['RUSSIAN FEDERATION','RU','RUS'], ['SAN MARINO','SM','SMR'],
        ['SAUDI ARABIA','SA','SAU'], ['SERBIA','RS','SRB'], ['SLOVAKIA (Slovak Republic)','SK','SVK'],
        ['SLOVENIA','SI','SVN'], ['SPAIN','ES','ESP'], ['SVALBARD AND JAN MAYEN ISLANDS','SJ','SJM'],
        ['SWEDEN','SE','SWE'], ['SWITZERLAND','CH','CHE'], ['SYRIAN ARAB REPUBLIC','SY','SYR'],
        ['TAJIKISTAN','TJ','TJK'], ['TURKEY','TR','TUR'], ['TURKMENISTAN','TM','TKM'], ['UKRAINE','UA','UKR'],
        ['UNITED ARAB EMIRATES','AE','ARE'], ['UNITED KINGDOM','GB','GBR'], ['UZBEKISTAN','UZ','UZB'],
		['YEMEN','YE','YEM']]

	afrinic = [['ALGERIA','DZ','DZA'], ['ANGOLA','AO','AGO'], ['BENIN','BJ','BEN'], ['BOTSWANA','BW','BWA'], 
		['BURKINA FASO','BF','BFA'], ['BURUNDI','BI','BDI'], ['CAMEROON','CM','CMR'], ['CAPE VERDE','CV','CPV'], 
		['CENTRAL AFRICAN REPUBLIC','CF','CAF'], ['CHAD','TD','TCD'], ['COMOROS','KM','COM'], ['CONGO','CG','COG'], 
		['CONGO, THE DEMOCRATIC REPUBLIC OF THE','CD','COD'], ["COTE D'IVOIRE ",'CI','CIV'], ['DJIBOUTI','DJ','DJI'], 
		['EGYPT','EG','EGY'], ['EQUATORIAL GUINEA','GQ','GNQ'], ['ERITREA','ER','ERI'], ['ETHIOPIA','ET','ETH'], 
		['GABON','GA','GAB'], ['GAMBIA','GM','GMB'], ['GHANA','GH','GHA'], ['GUINEA','GN','GIN'],
        ['GUINEA-BISSAU','GW','GNB'], ['KENYA','KE','KEN'], ['LESOTHO','LS','LSO'], ['LIBERIA','LR','LBR'],
        ['LIBYA','LY','LBY'], ['MADAGASCAR','MG','MDG'], ['MALI','ML','MLI'], ['MAURITANIA','MR','MRT'],
        ['MAURITIUS','MU','MUS'], ['MAYOTTE','YT','MYT'], ['MOROCCO','MA','MAR'], ['MOZAMBIQUE','MZ','MOZ'],
        ['NAMIBIA','NA','NAM'], ['NIGER','NE','NER'], ['NIGERIA','NG','NGA'], ['REUNION','RE','REU'],
        ['RWANDA','RW','RWA'], ['SAO TOME AND PRINCIPE','ST','STP'], ['SENEGAL','SN','SEN'], ['SEYCHELLES','SC','SYC'],
		['SIERRA LEONE','SL','SLE'], ['SOMALIA','SO','SOM'], ['SOUTH AFRICA','ZA','ZAF'], ['SOUTH SUDAN','SS','SSD'], 
		['SUDAN','SD','SDN'], ['SWAZILAND','SZ','SWZ'], ['TANZANIA, UNITED REPUBLIC OF','TZ','TZA'],
        ['TOGO','TG','TGO'], ['TUNISIA','TN','TUN'], ['UGANDA','UG','UGA'], ['WESTERN SAHARA','EH','ESH'],
        ['ZAMBIA','ZM','ZMB'], ['ZIMBABWE','ZW','ZWE']]

	apnic = [['AFGHANISTAN','AF','AFG'], ['AMERICAN SAMOA','AS','ASM'], ['AUSTRALIA','AU','AUS'],
        ['BANGLADESH','BD','BGD'], ['BHUTAN','BT','BTN'], ['BRITISH INDIAN OCEAN TERRITORY','IO','IOT'],
        ['BRUNEI DARUSSALAM','BN','BRN'], ['CAMBODIA','KH','KHM'], ['CHINA','CN','CHN'],
        ['CHRISTMAS ISLAND','CX','CXR'], ['COCOS (KEELING) ISLANDS','CC','CCK'], ['COOK ISLANDS','CK','COK'],
        ['FIJI','FJ','FJI'], ['FRENCH POLYNESIA','PF','PYF'], ['FRENCH SOUTHERN TERRITORIES','TF','ATF'],
		['GUAM','GU','GUM'], ['HONG KONG','HK','HKG'], ['INDIA','IN','IND'], ['INDONESIA','ID','IDN'],
        ['JAPAN','JP','JPN'], ['KIRIBATI','KI','KIR'], ["KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF ",'KP','PRK'],
        ['KOREA, REPUBLIC OF','KR','KOR'], ["LAO PEOPLE'S DEMOCRATIC REPUBLIC ",'LA','LAO'], ['MACAO','MO','MAC'],
        ['MALAYSIA','MY','MYS'], ['MALDIVES','MV','MDV'], ['MARSHALL ISLANDS','MH','MHL'],
        ['MICRONESIA, FEDERATED STATES OF','FM','FSM'], ['MONGOLIA','MN','MNG'], ['MYANMAR','MM','MMR'],
        ['NAURU','NR','NRU'], ['NEPAL','NP','NPL'], ['NEW CALEDONIA','NC','NCL'], ['NEW ZEALAND','NZ','NZL'],
		['NIUE','NU','NIU'], ['NORFOLK ISLAND','NF','NFK'], ['NORTHERN MARIANA ISLANDS','MP','MNP'],
        ['PAKISTAN','PK','PAK'], ['PALAU','PW','PLW'], ['PAPUA NEW GUINEA','PG','PNG'], ['PHILIPPINES','PH','PHL'],
        ['PITCAIRN','PN','PCN'], ['SAMOA','WS','WSM'], ['SINGAPORE','SG','SGP'], ['SOLOMON ISLANDS','SB','SLB'],
        ['SRI LANKA','LK','LKA'], ['TAIWAN, PROVINCE OF CHINA','TW','TWN'], ['THAILAND','TH','THA'],
        ['TIMOR-LESTE','TL','TLS'], ['TOKELAU','TK','TKL'], ['TONGA','TO','TON'], ['TUVALU','TV','TUV'],
		['VANUATU','VU','VUT'], ['VIET NAM','VN','VNM'], ['WALLIS AND FUTUNA ISLANDS','WF','WLF']]

	lacnic = [['ARGENTINA','AR','ARG'], ['ARUBA','AW','ABW'], ['BELIZE','BZ','BLZ'],
        ['BOLIVIA, PLURINATIONAL STATE OF','BO','BOL'], ['BONAIRE, SINT EUSTATIUS AND SABA','BQ','BES'],
        ['BRAZIL','BR','BRA'], ['CHILE','CL','CHL'], ['COLOMBIA','CO','COL'], ['COSTA RICA','CR','CRI'],
        ['CUBA','CU','CUB'], ['CURACAO','CW','CUW'], ['DOMINICAN REPUBLIC','DO','DOM'], ['ECUADOR','EC','ECU'],
        ['EL SALVADOR','SV','SLV'], ['FALKLAND ISLANDS (MALVINAS)','FK','FLK'], ['FRENCH GUIANA','GF','GUF'],
        ['GUATEMALA','GT','GTM'], ['GUYANA','GY','GUY'], ['HAITI','HT','HTI'], ['HONDURAS','HN','HND'],
        ['MEXICO','MX','MEX'], ['NICARAGUA','NI','NIC'], ['PANAMA','PA','PAN'], ['PARAGUAY','PY','PRY'],
        ['PERU','PE','PER'], ['SINT MAARTEN (DUTCH PART)','SX','SXM'],
        ['SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS','GS','SGS'], ['SURINAME','SR','SUR'],
        ['TRINIDAD AND TOBAGO','TT','TTO'], ['URUGUAY','UY','URY'], ['VENEZUELA, BOLIVARIAN REPUBLIC OF','VE','VEN']]

	result = []
	
	if len(country) == 2:
		if [i[0] for i in arin if i[1] == (country)]:
			result.append("ARIN")
			result.append([i[1] for i in arin if i[1] == (country)][0])
		elif [i[0] for i in ripe if i[1] == (country)]:
			result.append("RIPE")
			result.append([i[1] for i in ripe if i[1] == (country)][0])
		elif [i[0] for i in afrinic if i[1] == (country)]:
			result.append("AFRINIC")
			result.append([i[1] for i in afrinic if i[1] == (country)][0])
		elif [i[0] for i in apnic if i[1] == (country)]:
			result.append("APNIC")
			result.append([i[1] for i in apnic if i[1] == (country)][0])
		elif [i[0] for i in lacnic if i[1] == (country)]:
			result.append("LACNIC")
			result.append([i[1] for i in lacnic if i[1] == (country)][0])
		else:
			print "Country not found"

	elif len(country) == 3:
		if [i[0] for i in arin if i[2] == (country)]:
			result.append("ARIN")
			result.append([i[1] for i in arin if i[2] == (country)][0])
		elif [i[0] for i in ripe if i[2] == (country)]:
			result.append("RIPE")
			result.append([i[1] for i in ripe if i[2] == (country)][0])
		elif [i[0] for i in afrinic if i[2] == (country)]:
			result.append("AFRINIC")
			result.append([i[1] for i in afrinic if i[2] == (country)][0])
		elif [i[0] for i in apnic if i[2] == (country)]:
			result.append("APNIC")
			result.append([i[1] for i in apnic if i[2] == (country)][0])
		elif [i[0] for i in lacnic if i[2] == (country)]:
			result.append("LACNIC")
			result.append([i[1] for i in lacnic if i[2] == (country)][0])
		else:
			print "Country not found"

	else:
		if [i[0] for i in arin if i[0].startswith(country)]:
			result.append("ARIN")
			result.append([i[1] for i in arin if i[0].startswith(country)][0])
		elif [i[0] for i in ripe if i[0].startswith(country)]:
			result.append("RIPE")
			result.append([i[1] for i in ripe if i[0].startswith(country)][0])
		elif [i[0] for i in afrinic if i[0].startswith(country)]:
			result.append("AFRINIC")
			result.append([i[1] for i in afrinic if i[0].startswith(country)][0])
		elif [i[0] for i in apnic if i[0].startswith(country)]:
			result.append("APNIC")
			result.append([i[1] for i in apnic if i[0].startswith(country)][0])
		elif [i[0] for i in lacnic if i[0].startswith(country)]:
			result.append("LACNIC")
			result.append([i[1] for i in lacnic if i[0].startswith(country)][0])
		else:
			print "Country not found"
	return result

def ilookup(rir, countrycode):

	if rir in registrars:
		f = opener.open(registrars[rir])
		lines = f.readlines()
	
		for line in lines:
			if(('ipv4' in line) & (countrycode in line)):
				s=line.split("|")
				net=s[3]
				cidr=float(s[4])
				ipranges.append(IPNetwork("%s/%d" % (net,(32-math.log(cidr,2)))))
		sorted(ipranges)		

	else:
		print "\nError: Registrar not found\n"
		print "Valid registrars are: "
		for k in registrars.iterkeys(): print "\t",k

def whois(iprange):
	w = IPWhois(i[0])
	result = OrderedDict()

	try:
		if args.norws:
			x = w.lookup() #fallback to whois tcp_43
		else:
			x = w.lookup_rws() #default to whois RESTful Web Service tcp_80
	except WhoisLookupError:
		print "\nWhois Error"
		pass

	for k,v in x.iteritems():
		if k == 'nets':
			nets = v[0]

	if args.verbose:
		#Defining keys for OrderedDict
		result["Name"]= ""
		result["Description"] = ""
		result["Address"] = ""
		result["Postalcode"] = ""
		result["City"] = ""
		result["ASN"] = ""
		for k,v in nets.iteritems():
			if v is None: v = ""
			if k == 'name':
				result["Name"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
			if k == 'description':
				result["Description"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
			if k == 'address':
				result["Address"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
			if k == 'postal_code':
				result["Postalcode"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
			if k == 'city':
				result["City"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
		for k,v in x.iteritems():
			if k == 'asn':
				result["ASN"]= v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')

	else:
		result["Name"]= ""
		result["Description"] = ""
		for k,v in nets.iteritems():
			if v is None: v = ""
			if k == 'name':
				result["Name"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')
			elif k == 'description':
				result["Description"] = v.replace('\n', ',').replace('\r', ',').replace('\"', '_').replace('\'', '_')

	return result

	
if __name__ == "__main__":
    rir,countrycode = clookup(country)
    ilookup(rir, countrycode)
    if args.outputjson and args.whois:
        with open('rir_output_%s.jsn' % args.country.lower(), 'w') as outputfile:
            for i in ipranges:
                _iprange = ["IP Range"]
                _iprange.append([str(i)])
                _whois = ["Whois"]
                _whois.append(whois(i))
                _time = ["Timestamp"]
                _time.append([str(datetime.utcnow())])
                _result = []
                _result.append(_iprange)
                _result.append(_whois)
                _result.append(_time)
                outputfile.write(dumps(_result, indent=4))
                outputfile.write("\n")

    elif args.outputjson:
        with open('rir_output_%s.jsn' % args.country.lower(), 'w') as outputfile:
            for i in ipranges:
                _iprange = ["IP Range"]
                _iprange.append([str(i)])
                _time = ["Timestamp"]
                _time.append([str(datetime.utcnow())])
                _result = []
                _result.append(_iprange)
                _result.append(_time)
                outputfile.write(dumps(_result, indent=4))
                outputfile.write("\n")

    elif args.outputcsv and args.whois:
        with open('rir_output_%s.csv' % args.country.lower(), 'w') as outputfile:
            if args.verbose:
                outputfile.write("TIMESTAMP;RANGE;NAME;DESCRIPTION;ADRES;POSTALCODE;CITY;ASN\n")
                for i in ipranges:
                    _whois = whois(i)
                    _iprange = str(i)
                    _timestamp = (str(datetime.utcnow()))
                    outputfile.write("%s;%s;%s;%s;%s;%s;%s;%s\n" % (_timestamp,
                                            _iprange,
                                            _whois['Name'],
                                            _whois['Description'],
                                            _whois['Address'],
                                            _whois['Postalcode'],
                                            _whois['City'],
                                            _whois['ASN'],
                                            ))
            else:
                outputfile.write("TIMESTAMP;RANGE;NAME;DESCRIPTION\n")
                for i in ipranges:
                    _whois = whois(i)
                    _iprange = str(i)
                    _timestamp = (str(datetime.utcnow()))
                    outputfile.write("%s;%s;%s;%s\n" % 		(_timestamp,
                                            _iprange,
                                            _whois['Name'],
                                            _whois['Description'],
                                            ))

    elif args.outputcsv:
        with open('rir_output_%s.csv' % args.country.lower(), 'w') as outputfile:
            outputfile.write("RANGE;TIMESTAMP\n")
            for i in ipranges:
                _iprange = str(i)
                _timestamp = (str(datetime.utcnow()))
                outputfile.write("%s;%s\n" % (_iprange, _timestamp))

    elif args.whois:
        for i in ipranges:
            print "%s\t%s" % (i, whois(i))

    else:
        for i in ipranges:
            print i

