import logging
import random
from collections import defaultdict

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger('syml')


class StochasticSearch(ExplorationTechnique):
    """
    Stochastic Search.

    Will only keep one path active at a time, any others will be discarded.
    Before each pass through, weights are randomly assigned to each basic block.
    These weights form a probability distribution for determining which state remains after splits.
    When we run out of active paths to step, we start again from the start state.
    """

    def __init__(self, restart_prob=0.0001, **kwargs):
        """
        :param start_state:  The initial state from which exploration stems.
        :param restart_prob: The probability of randomly restarting the search (default 0.0001).
        """
        super(StochasticSearch, self).__init__()
        self.restart_prob = restart_prob
        self._random = random.Random()
        self._random.seed(42)
        self.affinity = defaultdict(self._random.random)

    def setup(self, simgr):
        super(StochasticSearch, self).setup(simgr)
        self.start_state = simgr.one_active

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if not simgr.stashes[stash] or self._random.random() < self.restart_prob:
            simgr.stashes[stash] = [self.start_state]
            self.affinity.clear()

        if len(simgr.stashes[stash]) > 1:
            def weighted_pick(states):
                """
                param states: Diverging states.
                """
                assert len(states) >= 2
                total_weight = sum((self.affinity[s.addr] for s in states))
                selected = self._random.uniform(0, total_weight)
                i = 0
                for i, state in enumerate(states):
                    weight = self.affinity[state.addr]
                    if selected < weight:
                        break
                    else:
                        selected -= weight
                picked = states[i]
                return picked

            simgr.stashes[stash] = [weighted_pick(simgr.stashes[stash])]

        return simgr