Will only keep one path active at a time, any others will be discarded.
Before each pass through, weights are randomly assigned to each basic block.
These weights form a probability distribution for determining which state remains after splits.
When we run out of active paths to step, we start again from the start state.