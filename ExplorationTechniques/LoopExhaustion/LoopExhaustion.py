
# https://raw.githubusercontent.com/ucsb-seclab/syml/main/syml/exploration/exploration_techniques/literature/aeg_loop_exhaustion.py

import logging

import angr
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger('LoopExhaustion')


class AEGLoopExhaustion(ExplorationTechnique):
    """
    Loop Exhaustion. http://security.ece.cmu.edu/aeg/aeg-current.pdf

    We propose and use a loop exhaustion search strategy. The loop-exhaustion
    strategy gives higher priority to an interpreter exploring the maximum number
    of loop iterations, hoping that computations involving more iterations
    are more promising to produce bugs like buffer overflows.
    Thus, whenever execution hits a symbolic loop, we try to exhaust the loopexecute
    it as many times as possible. Exhausting a symbolic loop has two immediate side effects:
    1) on each loop iteration a new interpreter is spawned, effectively causing an explosion
    in the state space, and 2) execution might get 'stuck' in a deep loop.
    To avoid getting stuck, we impose two additional heuristics during loop exhaustion:
    1) we use preconditioned symbolic execution along with pruning to reduce the number of interpreters or
    2) we give higher priority to only one interpreter that tries to fully exhaust the loop,
    while all other interpreters exploring the same loop have the lowest possible priority.
    """

    def __init__(self, **kwargs):
        super(AEGLoopExhaustion, self).__init__()
        self.top_count = 0

    def setup(self, simgr):
        super(AEGLoopExhaustion, self).setup(simgr=simgr)
        simgr.stashes['active'][0].globals['visits'] = dict()

        # setup LoopSeer
        simgr.stashes['active'][0].register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10000))

    @staticmethod
    def rank(s, reverse=False):
        k = -1 if reverse else 1
        return k * sum([s.loop_data.back_edge_trip_counts[loop[0].entry.addr][-1] for loop in s.loop_data.current_loop])

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.stashes[stash]) == 1:
            new_count = self.rank(simgr.stashes[stash][0])
            if new_count > self.top_count or len(simgr.stashes['deferred']) == 0:
                #l.debug(f'looping!')
                self.top_count = new_count
            else:
                #l.debug(f'exhausted or new loop!')  # \t {simgr.stashes[stash][0].loop_data.back_edge_trip_counts}')
                simgr.move(from_stash=stash, to_stash='deferred')
                simgr.split(from_stash='deferred', to_stash=stash, state_ranker=self.rank,
                            limit=len(simgr.deferred) - 1)
                self.top_count = self.rank(simgr.stashes[stash][0])

        elif len(simgr.stashes[stash]) == 0:
            #l.debug('exhausted?')
            simgr.split(from_stash='deferred', to_stash=stash, state_ranker=self.rank, limit=len(simgr.deferred) - 1)
            self.top_count = self.rank(simgr.stashes[stash][0])

        else:
            counts = simgr.stashes[stash][0].loop_data.back_edge_trip_counts
            for s in simgr.stashes[stash][1:]:
                if s.loop_data.back_edge_trip_counts != counts:
                    simgr.split(from_stash=stash, to_stash='deferred', state_ranker=lambda s: self.rank(s, reverse=True),
                                limit=1)
                    self.top_count = self.rank(simgr.stashes[stash][0])

                    l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.stashes[stash]}')
                    break
            else:
                #l.debug('one more step..and let\'s see what happens..')
                pass

        return simgr