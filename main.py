import requests
import json
import time
import pandas as pd
import config

def library_creation(threat, threat_id, threat_desc,usecase):

  api_endpoint = config.URL
  #adds the API token from a seperate file
  api_token = config.API_KEY

  #CREATES THE LIBRARY

  library_endpoint = api_endpoint + "/libraries"

  library = "CURRENT_CWE_LIST"
  library_ref = library.replace(" ","-")


  library_data = json.dumps({
    "ref" : library_ref,
    "name" : library,
    "desc" : ""
  })

  headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "API-token": f"{api_token}"
  }

  response = requests.post(library_endpoint, headers=headers, data=library_data)
  if response.status_code == 201:
    print(response, "Library was created")
  elif response.status_code == 400:
    print(response, "Library was not created")

  #time.sleep(2)

  #CREATES THE RISK PATTERN

  riskpattern_endpoint = api_endpoint + f"/libraries/{library_ref}/riskpatterns"

  #print(riskpattern_endpoint)

  riskpattern = "CWEs"
  riskpattern_ref = riskpattern.replace(" ", "")


  payload = json.dumps({
    "ref": riskpattern_ref,
    "name": riskpattern,
    "desc": "",
    #"tags": [
      #"string",
      #"string"
    #]
  })
  headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'API-token': api_token
  }

  response = requests.request("POST", riskpattern_endpoint, headers=headers, data=payload)
  print(response, "Risk Pattern")
  #print(response.text)


  #CREATES THE USE CASE

  usecase_endpoint = api_endpoint + f"/libraries/{library_ref}/riskpatterns/{riskpattern_ref}/usecases"

  usecase_ref = usecase.replace(" ", "")


  usecase_data = json.dumps({
    "ref": usecase_ref,
    "name": usecase,
    "desc": ""
  })

  response = requests.post(usecase_endpoint, headers=headers, data=usecase_data)
  print(response, "Use Case")

  #time.sleep(2)

  #CREATES THE THREATS

  threat_endpoint = api_endpoint + f"/libraries/{library_ref}/riskpatterns/{riskpattern_ref}/usecases/{usecase_ref}/threats"

  #print(threat_endpoint)

  #threat_ref = threat.replace(" ", "-")

  #the only values accepted for riskRating are "[The only risk rating acceptable values are: none, low, medium, high, very-high]"
  threat_data = json.dumps({
    "ref": f"CWE-{threat_id}",
    "name": f"{threat}",
    "desc": f"{threat_desc}",
    "riskRating": {
      "confidentiality": "high",
      "integrity": "high",
      "availability": "high",
      "easeOfExploitation": "low"
      }
    })

  response = requests.post(threat_endpoint, headers=headers, data=threat_data)
  print(response, "Threat")
  #print(response.text, "Threat Response")

  print(f"Row {counter} Complete")
  print("")


library_data = pd.read_excel(r"\\wsl.localhost\Ubuntu\home\jamesrabe\CWEParser_RABECO\output.xlsx", 'Sheet1')  # Replace 'your_spreadsheet.csv' with the actual file name and path

counter = 1

for index, row in library_data.iterrows():

  counter += 1

  #create a spreadsheet with column headers and match those the variables in this script.


  threat_id = str(row['id'])
  threat = str(row['name'])
  threat_desc = str(row['description'])
  usecase = str(row['usecase'])
  #reference = str(row['reference'])


  library_creation(threat, threat_id, threat_desc,usecase)