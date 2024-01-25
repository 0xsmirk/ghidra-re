#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

# Get the current program
program = currentProgram

# Get the current pcode function
function = getFunctionContaining(getInstructionAt(toAddr(program.getMinAddress())))

# Get the pcode instructions for the function
pcode = function.getPcode()

# Translate the pcode instructions into Python code
python_code = []
for instr in pcode:
    python_code.append(str(instr))

# Print the generated Python code
print("\n".join(python_code))
