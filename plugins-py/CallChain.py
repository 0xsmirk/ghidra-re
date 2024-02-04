# Display call chain graph between two functions and output to the console.
#@author smile
#@category VulAnalysize
#@menupath VulAnalysize.Call Chain


from ghidra.util.graph import DirectedGraph, Vertex, Edge
from ghidra.graph.viewer import GraphComponent
from ghidra.program.model.address import Address

import __main__ as ghidra_app

found_call_chain = False

def get_references(caller, callee):
    """
    Find reference addresses between a caller function and callee function.

    :param caller: Caller function.
    :param callee: Callee function.

    :return: List of addresses where the caller calls the callee.
    :rtype: list
    """
    function_manager = currentProgram.getFunctionManager()

    ref_list = []
    callee_symbol = callee.getSymbol()
    callee_references = callee_symbol.getReferences()

    for ref in callee_references:
        addr = ref.getFromAddress()
        func = function_manager.getFunctionContaining(addr)
        if func == caller:
            ref_list.append(addr)

    return ref_list


def print_call_chain(call_chain):
    """
    Print successful call chains to the console and add to the graph.

    :param call_chain: Successful call chain.
    :param dot: Call graph.
    """
    previous_function = None
    function_references = {}
    function_chain = []

    for function in call_chain:
        if previous_function:
            function_references[str(previous_function)] = get_references(
                previous_function, function)

        previous_function = function
        function_chain.append(str(function))


    for function in function_chain:
        print function,
        if function in function_references:
            print function_references[function],
            print ' -> ',
    print ''


def call_chain_recurse(call_chain, complete_call):
    """
    Recurse from call_chain to complete_call, if found.

    :param call_chain: Current call chain.
    :param complete_call: Call that indicates a successfully completed chain.
    :param dot: Call graph
    """

    global found_call_chain

    function_list = call_chain[0].getCallingFunctions(monitor)

    for func in function_list:
        if func == complete_call:
            print_call_chain([func] + call_chain)
            found_call_chain = True
            continue

        if func in call_chain:
            continue
        call_chain_recurse([func] + call_chain, complete_call)


def discover_call_chain(from_function, to_function):
    """
    Discover call chains between two functions.

    :param from_function: Function start looking for path to next function.
    :param to_function: Function that, when/if found, indicates a chain.
    """
    call_chain_recurse([to_function], from_function)


def run():
    # get script params
    args = ghidra_app.getScriptArgs()
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
    else:
        vul_func = args[0]

    print(vul_func)
    print(args)

    # begin analysis
    func_man = currentProgram.getFunctionManager()

    function_list = [function for function in func_man.getFunctions(True)]
    function_list.sort(key=lambda func: str(func))


    for func in function_list:
        if func.getName() == 'main' or func.getName() == 'entry':
            print("Function Name is: {}, function type is :{}, function's address is: {}".format(func, type(func), func.getBody()))
            from_function = func



    function_list.remove(from_function)

    to_function = func_man.getFunctionAt(currentProgram.getAddressFactory().getAddress("0x000093fc"))

    print 'Finding x-refs from %s to %s\n' % (from_function, to_function)

    discover_call_chain(from_function, to_function)

# Starts execution here
if __name__ == '__main__':
    run()