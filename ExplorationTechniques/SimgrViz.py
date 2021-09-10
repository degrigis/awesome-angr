# pylint: disable=import-error, no-name-in-module
import angr
import hashlib
import os
import logging
import networkx
import time
import copy

from typing import List, Set, Dict, Tuple, Optional
from angr.exploration_techniques import ExplorationTechnique
from angr import SimState
from networkx.drawing.nx_agraph import write_dot

from shutil import which

l = logging.getLogger("SimgrViz")
l.setLevel("INFO")

WDIR = './'
RET_ADDR = 0xdeadbeef

class SimgrViz(ExplorationTechnique):
    '''
    When plugging this Exploration technique we collect information
    regarding the SimStates generated by the Simgr.
    This is a DEBUG ONLY technique that should never be used in production.
    '''
    def __init__(self, cfg=None):
        super(SimgrDebugger, self).__init__()
        self._simgrG = networkx.DiGraph()
        self.cfg = cfg
        # Boolean guard to understand if this is the initial state or not.
        self._start = True
        self._salt = 0
        self._path_exploration_id = 0

        # Reference to the taint tracker to extract info
        self.taint_tracker = None

        # TODO
        # Activate the visualization only when _starts_from is reached.
        self._starts_from = None
        # De-activate the visualizaton when _ends_to is reached.
        self._ends_to = None

        self.last_seen_id = None

    def setup(self, simgr):
        for state in simgr.stashes['active']:
            state.globals["predecessor"] = None
            state.globals["path_exploration_id"] = self._path_exploration_id
        self._path_exploration_id += 1
        return

    def get_state_hash(self, state):
        reg_values = []
        for r in state.project.arch.register_list:
            reg_values.append(state.registers.load(r.name))
        regs = '-'.join([str(x) for x in reg_values ])
        stack_signature = '-'.join([
                                   hex(state.callstack.call_site_addr),
                                   hex(state.callstack.current_return_target),
                                   hex(state.callstack.current_stack_pointer),
                                   str(state.callstack.jumpkind),
                                   hex(state.callstack.ret_addr),
                                   ])
        globals_signature = '-'.join([ str(x) for x in state.globals.values()])
        state_id_sig = str(id(state)) # regs + str(id(state)) # + stack_signature # + globals_signature
        h = hashlib.sha256()
        h.update(state_id_sig.encode("utf-8"))
        h.update(regs.encode("utf-8"))
        h.update(stack_signature.encode("utf-8"))
        h.update(globals_signature.encode("utf-8"))
        if state.globals["predecessor"]:
            h.update(state.globals["predecessor"].encode("utf-8"))
        h_hexdigest = h.hexdigest()
        # Store the signature into the state.
        state.globals["state_signature"] = h_hexdigest
        return str(h_hexdigest)

    def _update_timeout_info(self, timeout_states: List[SimState]):
        for state in timeout_states:
            s_sig = state.globals["state_signature"]
            self._simgrG.nodes[s_sig]["timeout"] = True

    def _add_state_to_graph(self, parent_state_id:str, sim_state_id:str, state:SimState):

        self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr))
        self._simgrG.add_edge(parent_state_id, sim_state_id)

        if state.addr in self.cfg.functions:
            self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr), color = "green" if state.project.is_hooked(state.addr) else "yellow",
                                                func_name="{}".format(self.cfg.get_any_node(state.addr).name),
                                                hooked = True if state.project.is_hooked(state.addr) else False,
                                                call_followed = True,
                                                path_exploration_id=state.globals["path_exploration_id"])
        else:
            self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr), path_exploration_id=state.globals["path_exploration_id"])

        self._simgrG.nodes[sim_state_id]['jumpkind'] = state.history.jumpkind

        if state.loop_state_vars.loop_handler_check_loop:
            self._simgrG.nodes[sim_state_id]["loop_handler_check_loop"] = str(state.loop_state_vars.loop_handler_check_loop)

        # This can be heavy
        if state.addr != RET_ADDR:
            self._simgrG.nodes[sim_state_id]['bb_ins'] = [x.mnemonic for x in state.block().disassembly.insns]
            self._simgrG.nodes[sim_state_id]['bb_size'] = state.block().size
            if state.callstack.current_function_address:
                self._simgrG.nodes[sim_state_id]['callstack_curr_func_addr'] = str(hex(state.callstack.current_function_address))

    def _tag_fake_ret(self, state:SimState):
        if state.history.jumpkind == "Ijk_FakeRet":
            self._simgrG.nodes[state.globals["state_signature"]]['call_followed'] = False
            self._simgrG.nodes[state.globals["state_signature"]]['color'] = "red"

    def successors(self, simgr, state:SimState, **kwargs):
        succs = simgr.successors(state, **kwargs)
        self._tag_fake_ret(state)
        if self._start:
            assert(not state.globals["predecessor"])
            sim_state_id = self.get_state_hash(state)

            if state.addr in self.cfg.functions:
                if state.project.is_hooked(state.addr):
                    self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr), color = "green",
                                                        hooked = True,
                                                        func_name="{}".format(self.cfg.get_any_node(state.addr).name))
                else:
                    self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr), color = "yellow",
                                                        hooked = False,
                                                        func_name="{}".format(self.cfg.get_any_node(state.addr).name))
            else:
                self._simgrG.add_node(sim_state_id, state_addr = hex(state.addr))

            self._start = False

        self._path_exploration_id += 1

        for succ_state in succs.flat_successors:
            succ_state.globals["predecessor"] = state.globals["state_signature"]
            parent_state_id = succ_state.globals["predecessor"]
            succ_state.globals["path_exploration_id"] = self._path_exploration_id
            sim_state_id = self.get_state_hash(succ_state)

            self._add_state_to_graph(parent_state_id, sim_state_id, succ_state)

        return succs
