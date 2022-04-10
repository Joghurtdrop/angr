# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import sys

def main(argv):

  path_to_binary = argv[1] # :string
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  simulation = project.factory.simgr(initial_state, veritesting=True)

  print_good_address = 0x08049374
  simulation.explore(find=print_good_address)

  if simulation.found:
    solution_state = simulation.found[0]

    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    raise Exception('No solution found.')

if __name__ == '__main__':
  main(sys.argv)