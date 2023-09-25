import angr
from python import embed
import logging

logging.getlogger('angr').setLevel('INFO')
project = angr.Project("./x0rr3al.1", main_opts={'base_addr': 0}, auto_load_libs=True)

initial_state = project.factory.entry_state()
print(initial_state)

sm = project.factory.simgr(initial_state)

good_address = 0x01b62

avoid_address = [0x16ad, 0x156a]
sm.explore(find=good_address, avoid=avoid_address)
print(sm.found[0].posix.dumps(0))
