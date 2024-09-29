#T21 Estrella Díaz 2065722
import requests
import json
import logging
import getpass
import re
import os

print('your logs will be stored in ',os.getcwd())
 
#apikey = 'ec1e2ebed1754f1b8c00f2b90aa15906'
headers = {}
headers['content-type'] = 'application/json'
headers['api-version'] = '3'
headers['User-Agent'] = 'python'

#error logs basic config
logging.basicConfig(filename='hibpERROR.log',
                    format="%(asctime)s %(message)s",
                    datefmt="%m/%d/%Y %H:%M:%S",
                    level=logging.ERROR)

while True:
    apikey = getpass.getpass(prompt = '>> enter hibp apikey: ')

    #validate 'apikey' format
    if re.match(r'^[a-fA-F0-9]{32}$', apikey):
        #add to headers
        headers['hibp-api-key'] = apikey
        break
    else:
        print('ALERT!! your string is not apikey.')

try:
    #ask e-mail to be analyzed
    email = input('>> enter the e-mail to be investigated: ') #'falso@hotmail.com'
    #make the request
    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'+\
    email+'?truncateResponse=false'
    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()
        found = len(data)
        if found > 0:
            print('websites that ',email,' has been filtered are: ')
        else:
            print(email,' has not been filtered :D')
        
        for filtered in data:
                print(filtered['Name'])
                print(filtered['Domain'])
                print(filtered['BreachDate'])
                print(filtered['Description'])

                msg = email + ' found breaches: ' + str(found)
                print(msg)

                #create report .log
                logging.basicConfig(filename = 'hibpINFO.log',
                                    format="%(asctime)s %(message)s",
                                    datefmt="%m/%d/%Y %I:%M:%S %p",
                                    level=logging.INFO)
                logging.info(msg)
                print('report successfully created')
    else:
        msg = r.text
        print(msg)
        logging.error(msg)
        print('errors report successfully created')

except requests.exceptions.HTTPError as herr:
    msg = f"HTTP error: {herr}"
    print(msg)
    logging.error(msg)
    print('errors report successfully created')
except requests.exceptions.ConnectionError as cerr:
    msg = f"Connection error: {cerr}"
    print(msg)
    logging.error(msg)
    print('errors report successfully created')
except Exception as err:
    msg = f":O unexpected error: {err}"
    print(msg)
    logging.error(msg)
    print('errors report successfully created')
finally:
    #terminates logs correctly
    logging.shutdown()
    print('analysis completed...')