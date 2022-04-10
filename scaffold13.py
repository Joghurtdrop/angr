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

# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.
  
  project.hook(addr=0x080514D0, hook=angr.SIM_PROCEDURES['libc']['printf']())
  project.hook(addr=0x08051520, hook=angr.SIM_PROCEDURES['libc']['scanf']())
  project.hook(addr=0x0805EE70, hook=angr.SIM_PROCEDURES['libc']['puts']())
  project.hook(addr=0x0804A250, hook=angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

   
  print_good_address = 0x08049F01
  simulation.explore(find=print_good_address)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    raise Exception('No solution found.')

if __name__ == '__main__':
  main(sys.argv)