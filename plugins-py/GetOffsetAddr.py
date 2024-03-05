#TODO Get offset address
#@author smile
#@category Address

from ghidra.program.model.address import GenericAddress
#TODO Add User Code Here

# Get the address corresponding to the mouse
currentAddr = currentLocation.getAddress()

# Get the segment address of the corresponding address
segment_address = currentProgram.getMemory().getBlock(currentAddr).getStart()

# Get relative offset address
offset_address = currentAddr.subtract(segment_address)

print("relative offset address:{}".format(hex(offset_address).rstrip("L")))