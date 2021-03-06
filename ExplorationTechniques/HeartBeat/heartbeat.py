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


l = logging.getLogger("HeartBeat")
l.setLevel("INFO")

global CURR_SIMGR
global CURR_PROJ
global CURR_STATE

# This is useful if you plugged this: 
# https://github.com/degrigis/awesome-angr/tree/main/ExplorationTechniques/SimgrViz
def dump_viz_graph(simgr=None):
    l.info("Dumping visualization graph if it exists")
    
    if simgr is None:
        simgr = CURR_SIMGR
    
    for et in simgr._techniques:
        if "SimgrViz" in str(et):
            break
    write_dot(et._simgrG,"/tmp/my_simgr.dot")

# This is useful if you are using this:
# https://github.com/fmagin/angr-cli
def spw_cli():
    global CURR_SIMGR
    global CURR_PROJ
    global CURR_STATE
    import angrcli.plugins.ContextView
    from angrcli.interaction.explore import ExploreInteractive
    e = ExploreInteractive(CURR_PROJ, CURR_STATE)
    e.cmdloop()

class HeartBeat(ExplorationTechnique):

    def __init__(self, beat_interval=100):
        super(HeartBeat, self).__init__()
        self.stop_heart_beat_file = "/tmp/stop_heartbeat.txt"
        self.beat_interval = beat_interval
        self.beat_cnt = 0
        self.steps_cnt = 0

    def setup(self, simgr):
        return True

    def successors(self, simgr, state:SimState, **kwargs):
        succs = simgr.successors(state, **kwargs)
        self.beat_cnt += 1
        self.steps_cnt += 1
        if self.beat_cnt == self.beat_interval:
            l.info("Exploration is alive <3. Step {}".format(self.steps_cnt)) 
            l.info("    Succs are: {}".format(succs))
            l.info("    Simgr is: {}".format(simgr))
            self.beat_cnt = 0
            if os.path.isfile(self.stop_heart_beat_file):
                l.info("HeartBeat stopped, need help? </3")
                
                global CURR_SIMGR
                global CURR_PROJ
                global CURR_STATE

                CURR_SIMGR = simgr
                CURR_PROJ = state.project
                CURR_STATE = state
                
                import ipdb; ipdb.set_trace()
                
                CURR_SIMGR = None
        
        return succs
