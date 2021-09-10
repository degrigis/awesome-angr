from angr.exploration_techniques import ExplorationTechnique

class ExplosionDetector(ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=100):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()
        self.timed_out_bool = False

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0
        if len(simgr.unconstrained) > 0:
            l.debug("Nuking unconstrained")
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)
        if self.timed_out.is_set():
            l.critical("Timed out, %d states: %s" % (total, str(simgr)))
            self.timed_out_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)
        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            l.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        return simgr