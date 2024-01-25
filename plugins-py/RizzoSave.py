# Create "fuzzy" function signatures that can be shared an applied amongst different Ghidra projects.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Save Signatures

from utils import rizzo

# file_path = askFile('Save signature file as', 'OK').path
file_path = "/home/smile/Desktop/"+currentProgram.getExecutablePath().split("/")[-1]+".riz" 
if not file_path.endswith('.riz'):
    file_path += '.riz'

print('Building Rizzo signatures, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)
print(rizz)
rizz.save(file_path)
