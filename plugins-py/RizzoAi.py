# Apply "fuzzy" function signatures from a different Ghidra project.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Signatures


from utils import rizzo
import urllib2
import json
import pickle

print("RizzoAi Plug Test!!")

# Get Rizzo Signatures from McuAi
url = 'http://192.168.1.6:8000/get_rizzo/'+str(currentProgram.getLanguageID())
print(url)

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'}
request = urllib2.Request(url=url, headers=headers)
mcuai_response = urllib2.urlopen(request)
mcuai_body=mcuai_response.read()
mcuai_body_json = json.loads(mcuai_body.decode("utf-8"))

print('Applying Rizzo signatures, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)

# get mcuai_response's all rizzo
for mcu in mcuai_body_json:
    rizzo_str=rizz.ai_load(mcu['rizzo'])
    
    # apply signature to firmware
    rizz.apply(rizzo_str)

