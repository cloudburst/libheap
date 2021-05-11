import sys
import os

module_path = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
if module_path not in sys.path:
    #print("DEBUG: adding module path...")
    sys.path.insert(0, module_path)
#print(sys.path) # DEBUG

from libheap import *
