import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

def get_arch():
    return gdb.execute("maintenance info sections ?", to_string=True).strip().split()[-1:]

def get_size_sz():
    try:
        _machine = get_arch()[0]
    except IndexError:
        _machine = ""
        SIZE_SZ = 0

    if "elf64" in _machine:
        SIZE_SZ = 8
    elif "elf32" in _machine:
        SIZE_SZ = 4
    else:
        SIZE_SZ = 0

    return SIZE_SZ

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print_error("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print_error("This gdb's python support is too old.")
        sys.exit()
