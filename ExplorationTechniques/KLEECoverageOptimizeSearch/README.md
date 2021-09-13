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