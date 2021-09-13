import logging
import random
from itertools import cycle

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger('KLEECoverageOS')


class KLEECoverageOptimizeSearch(ExplorationTechnique):
    """
    Coverage Optimize Search. https://hci.stanford.edu/cstr/reports/2008-03.pdf

    A strategy which attempts to select states that are likely to cover new code
    in the immediate future. Heuristics are used to compute a weight for each process
    and a random process is selected according to these weights.
    Currently these heuristics use a combination of the minimum distance
    to an uncovered instruction, taking into account the call stack of the
    process, and whether the process has recently covered new code.
    These strategies are composed by selecting from each in a round robin fashion.
    Although this interleaving may increase the time for a particularly effective
    strategy to achieve high coverage, it protects the system against cases where
    one individual strategy would become stuck.
    Furthermore, because the strategies are always selecting processes from the same pool,
    using interleaving allows the strategies to interact cooperatively.
    Finally, once selected each process is run for a "time slice" defined by
    both a maximum number of instructions and a maximum amount of time.
    The time to execute an individual instruction can vary widely between
    simple instructions, like addition, and instructions which may use the
    constraint solver or fork, like branches or memory accesses.
    Time-slicing processes helps ensure that a process which is frequently
    executing expensive instructions will not dominate execution time.

    This is implemented as a Non-Uniform-Random-Search with interleaved heuristics:
        1. md2u: minimum distance to uncovered instruction
        2. covnew: recently covered new code
    TODO: a time/instruction batch limit may be set (default to false, user-set)
    """

    def __init__(self, **kwargs):
        super(KLEECoverageOptimizeSearch, self).__init__()
        self.heuristics = cycle(['md2u', 'covnew'])
        self.curr_heuristic = None
        self.covered = set()
        self.cfg = None

    def setup(self, simgr):
        super(KLEECoverageOptimizeSearch, self).setup(simgr)
        self.cfg = simgr._project.analyses.CFGFast(base_state=simgr.one_active, fail_fast=True, normalize=True)
        
    def rank(self, s, reverse=False):
        k = -1 if reverse else 1
        return k * s.globals[self.curr_heuristic]

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        # if there's no branch: update globals and go on
        if len(simgr.stashes[stash]) == 1:
            self.update_globals(simgr.stashes[stash][0])
            return simgr

        # if there are no successors: SHARED CODE AFTER IF STMT
        elif len(simgr.stashes[stash]) == 0:
            pass

        # if there is more than one successor: update globals, SHARED CODE AFTER IF STMT
        elif len(simgr.stashes[stash]) > 1:
            for state in simgr.stashes[stash]:
                self.update_globals(state)

        # change heuristic
        self.curr_heuristic = next(self.heuristics)

        # weighted choice
        simgr.move(from_stash=stash, to_stash='deferred')
        n = random.uniform(0, sum([s.globals[self.curr_heuristic] for s in simgr.stashes['deferred']]))
        for s in simgr.stashes['deferred']:
            if n < s.globals[self.curr_heuristic]:
                simgr.stashes['deferred'].remove(s)
                simgr.stashes[stash] = [s]
                l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.stashes[stash]} [{self.curr_heuristic} {s.globals[self.curr_heuristic]}]')
                break
            n = n - s.globals[self.curr_heuristic]

        return simgr

    def update_globals(self, state):
        # if new, update covered blocks, set insns since new code to 0
        if state.addr not in self.covered:
            self.covered.add(state.addr)
            state.globals['insns_since_new'] = 0
        # if not new: update insns since new code
        else:
            state.globals['insns_since_new'] = state.globals.get('insns_since_new', 0) + state.block().instructions

        state.globals['covnew'] = 1. / max(1, state.globals['insns_since_new'] - 1000)
        state.globals['covnew'] *= state.globals['covnew']
        state.globals['md2u'] = 1. / min(self.get_md2u(state.addr), 10000) or 1
        state.globals['md2u'] *= state.globals['md2u']

    def get_md2u(self, addr, iter=50):
        if iter == 0:
            return float('inf')

        if addr not in self.covered:
            return 0

        node = self.cfg.model.get_any_node(addr, anyaddr=True)
        md2u = float('inf')

        for succ in set(node.successors):
            md2u = min(md2u, self.get_md2u(succ, iter=iter - 1))

        return md2u + node.block.instructions if node.block else 10