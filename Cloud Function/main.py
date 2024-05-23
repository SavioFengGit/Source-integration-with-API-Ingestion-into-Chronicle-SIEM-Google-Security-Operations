# Imports required for the sample - Google Auth and API Client Library Imports.
# Get these packages from https://pypi.org/project/google-api-python-client/ or run $ pip
# install google-api-python-client from your terminal
from google.oauth2 import service_account
import re
import requests
import json
import utils
import time
from datetime import datetime, timedelta
import os
import base64
from google.auth.transport.requests import AuthorizedSession
SCOPES = ['https://www.googleapis.com/auth/malachite-ingestion']

# Environment variables
ENV_CHRONICLE_CUSTOMER_ID = "CHRONICLE_CUSTOMER_ID"
ENV_CHRONICLE_REGION = "CHRONICLE_REGION"
ENV_CHRONICLE_SERVICE_ACCOUNT = "CHRONICLE_SERVICE_ACCOUNT"
ENV_CTM_KEY_ID = "CTM_KEY_ID"
ENV_CTM_COLLECTION_ID = "CTM_COLLECTION_ID"
ENV_CTM_NEXT = "CTM_NEXT"

start_time = (datetime.now() - timedelta(minutes=60)).isoformat() #last 60 minutes
customer_id = utils.get_env_var(ENV_CHRONICLE_CUSTOMER_ID, is_secret=True)
region = utils.get_env_var(ENV_CHRONICLE_REGION)
credentials_file = utils.get_env_var(ENV_CHRONICLE_SERVICE_ACCOUNT, is_secret=True)
credentials_file = json.loads(credentials_file)
collection_id = utils.get_env_var(ENV_CTM_COLLECTION_ID, is_secret=True)
secret_id = utils.get_env_var(ENV_CTM_KEY_ID, is_secret=True)

credentials = service_account.Credentials.from_service_account_info(credentials_file, scopes=SCOPES)
auth_session = AuthorizedSession(credentials)
max_size = 1048576 #the post request can handle only 1mb
events =[]
timeout_function = 3000 #3600 -> 60min max 2° gen CF timeout
start_time_function = time.time()


import functions_framework
@functions_framework.http
def main(req): 
    print("Start Fetching IOC")
    CTM_NEXT = os.environ[ENV_CTM_NEXT]
    next_indicator=""
    next=""
    try:
        next_indicator = utils.get_env_var(ENV_CTM_NEXT, is_secret=True)
    except Exception as e:
        print(f"Indicator secret not present, get all data from CTM360! error -> {e}")
        if not str(e).endswith("has no versions."):
            utils.create_secret(CTM_NEXT.split("/")[1], "CTM_NEXT")
    
    next=next_indicator

    url_get=f"your_url_get"
    if next == "NO MORE DATA":
        print(f"Intermediary next indicator not present, fetching from {start_time} timestamp")
        url_get += f"?added_after={start_time}"
    elif next != "":
        next=next_indicator
        print(f"Present and intermediary next, start fetching using [{next}] next value")
        url_get+=f"?next={next}"
    

   

    url_post = f"{utils.instance_region(region)}/v2/entities:batchCreate"
    headers_get = {
        'Authorization': f'Bearer {secret_id }'
    }
    headers_post = {"Content-Type": "application/json"}


    # HTTP GET REQ (url_get,headers_get)
    more = True
    while more:
        response = requests.get(url_get, headers=headers_get)
        events = [] #need empty for the next loop
        #print(url_get)

        if response.status_code == 200:
            data = response.json()

            # PARSING JSON
            #print("Start converting attributes in UDM attributes")
            for obj in data['objects']:
                if obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['main_observable_type'] not in ["StixFile","Url","Domain-Name","IPv4-Addr","Hostname","Email-Addr"]:
                    print("object not supported -> ", obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['main_observable_type'])
                    continue
                metadata = {}
                file = {}
                threat = {}
                interval = {}
                entity = {}
                user = {}
                additionals = {}

                # >>> METADATA
                metadata['vendor_name'] = "CTM_CUSTOM_IOC"
                metadata['product_name'] = "CTM_CUSTOM_IOC"
                metadata['collected_timestamp'] = utils.now()
                metadata['product_entity_id'] = obj['id']

                # metadata.threat
                threat['confidence_details'] = str(obj['confidence'])
                threat['first_discovered_time'] = obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['created_at']
                threat['last_updated_time'] = obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['updated_at']

                # additionals

                additionals['score'] = obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['score']
                try:
                     additionals['description'] = obj['description']
                except KeyError:
                     pass
                additionals['extension_type'] = obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['extension_type']
                additionals['type'] = obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['type']
                additionals['detection'] = str(obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['detection'])
                try:
                     additionals['labels'] = obj['labels']
                except KeyError:
                     pass
                additionals['pattern'] = obj['pattern']
                additionals['pattern_type'] = obj['pattern_type']
                try:
                     additionals['pattern_version'] = obj['pattern_version']
                except KeyError:
                     pass
                        # >>> ENTITY
                        # - entity.type
                match obj['extensions']['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']['main_observable_type']:
                    case "StixFile":
                        #entity['file'] = obj['name']
                        try:
                            file['sha256'] = obj['name']
                        except KeyError:
                            pass
                        metadata['entity_type'] = 'FILE'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                    case "Url":
                        entity['url'] = obj['name']
                        metadata['entity_type'] = 'URL'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                    case "Domain-Name":
                        entity['hostname'] = obj['name']
                        metadata['entity_type'] = 'DOMAIN_NAME'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                    case "IPv4-Addr":
                        match = re.search(r"(\d+\.\d+\.\d+\.\d+)",obj['name'])
                        obj['name']= match.group(1)
                        entity['ip'] = obj['name']
                        metadata['entity_type'] = 'IP_ADDRESS'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                    case "Hostname":
                        entity['hostname'] = obj['name']
                        metadata['entity_type'] = 'DOMAIN_NAME'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                    case "Email-Addr":
                        user["emailAddresses"] = [obj["name"]]
                        metadata['entity_type'] = 'USER'
                        interval['start_time'] = obj['valid_from']
                        interval['end_time'] = obj['valid_until']

                # build the top level UDM Objects
                metadata['threat'] = [threat]
                metadata['interval'] = interval
                entity['file'] = file
                entity['user'] = user
                #create the final UDM event
                event = {}

                event['metadata'] = metadata
                event['entity'] = entity
                event['additional'] = additionals    
                log = json.dumps(event)
                events.append(json.loads((log)))
                #print(events)
                #print(len(events))
            #manage the max 1mb post data for request
            for chunk in utils.chunked_events(events, max_size):
                post_data = {
                "customer_id": customer_id,
                "log_type": "STIX",
                "entities": chunk
                }
            
            
        
                #PERFORM HTTP POST REQUEST (url_post,post_data, headers)
                post_response = auth_session.post(url_post, json=post_data, headers=headers_post)
                if post_response.status_code == 200:
                    print(f"sent {len(chunk)} data to SIEM")
                else:
                    print(f"POST error code: {post_response.status_code}")
                    print(f"POST error text: {post_response.text}")
                    return post_response.text,post_response.status_code

                #print(len(events))
                print(f"sent {len(chunk)} data to SIEM")
                print(data['next'])

                if data['more'] == True:
                    if int(time.time() - start_time_function) >= timeout_function:
                        print('TIMEOUT FUNCTION! updating CTM_NEXT secret..')
                        utils.update_secret("/".join(CTM_NEXT.split("/")[:4]), data['next'])
                        return "TIMEOUT"
                    next = data['next']
                    url_get=f"url_get?next={next}"
                else:
                    more = False
                    print('no more data to sent')
                    if next_indicator != "NO MORE DATA":
                        utils.update_secret("/".join(CTM_NEXT.split("/")[:4]), "NO MORE DATA")
                    break
                
            
        else:
            print(f"Error GET: {response.text}")
            return f"response.status_code"
    return "ok"


      