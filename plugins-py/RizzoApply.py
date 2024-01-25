# Apply "fuzzy" function signatures from a different Ghidra project.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Signatures


from utils import rizzo

# file_path = askFile('Load signature file', 'OK').path
file_path =  "/home/smile/Desktop/CAN_TC275.riz"

print('Applying Rizzo signatures, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)
signatures = rizz.load(file_path)
rizz.apply(signatures)
