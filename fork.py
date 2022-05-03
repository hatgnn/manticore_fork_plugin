import os
from manticore.core.plugin import Plugin
from manticore.core.smtlib import issymbolic, taint_with, istainted
from web3 import Web3
w3 = Web3(Web3.WebsocketProvider(os.environ.get("RPC_URL", "")))

class ForkPlugin(Plugin):
    """
    Reads data from the network, if data is not present with manticore.
    CALL, STATICCALL, EXTCODESIZE opcodes download the contract from network.
    SLOAD operation checks whether data is available, if not it gets from the network.

    Usually the network calls originate from any of the call opcodes(CALL, STATICCALL, etc), from EXTCODESIZE, EXTCODECOPY,
    SLOAD.

    MLOAD, MSTORE, SSTORE should work with the data already available to manticore.

    CALL -> Download the Code from Network -> Work Locally -> SLOAD -> Read From Network
    """
    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "EXTCODESIZE": 
            """
            Usually this opcode is called before an external call
            """
            target_addr = arguments[0]
            self.import_code_from_network(state, target_addr)

        if instruction.semantics == "STATICCALL":
            target_addr = arguments[1]
            self.import_code_from_network(state, target_addr)

        if instruction.semantics == "CALL":
            target_addr = arguments[1]
            self.import_code_from_network(state, target_addr)

    def will_evm_read_storage_callback(self, state, address, offset):
        '''
        Check whether a local value is present. If no value is present
        and if it is not read from chain before, we will get the onchain data.

        The value read from chain is tainted to prevent overwritting the locally calculated value.
        '''
        local_value=state.platform.get_storage_data(address, offset)
        if local_value.value == 0 and not istainted(local_value,"PLUGIN:READ_FROM_CHAIN"):
            value=w3.eth.get_storage_at(w3.toChecksumAddress(hex(address)), offset)
            value_int=int.from_bytes(value, byteorder='big')
            tainted_value=taint_with(value_int, "PLUGIN:READ_FROM_CHAIN")
            state.platform.set_storage_data(address, offset, tainted_value)

    def import_code_from_network(self, state, target_addr):
        """
        Checks whether the address is initialised already.
        If it is not initialised, plugin will import code from the network.
        """
        if not issymbolic(target_addr):
            try:
                state.platform.has_code(target_addr)
            except KeyError:
                """ 
                Reaches this block if the address was not initialised before.
                Not checking for the code length(outside "except") because of cases involving selfdestruct().
                
                Self destructed addresses will still be present in 'evm._world_state'.
                
                Will not get code if, 
                    1. Initialised either by manticore or plugin
                    2. Initialised and self destructed
                """
                checksummed_addr = w3.toChecksumAddress(hex(target_addr))
                runtime_code = w3.eth.get_code(checksummed_addr)
                state.platform.create_account(address=target_addr, code=runtime_code)