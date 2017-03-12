class pydbg:
    def __init__(self, debugger):
        self.debugger = debugger

    def format_address(self, value):
        return self.debugger.format_address(value)

    def get_heap_address(self, mp=None):
        return self.debugger.get_heap_address(mp)

    def get_inferior(self):
        return self.debugger.get_inferior()

    def get_size_sz(self):
        return self.debugger.get_size_sz()

    def read_memory(self, address, length):
        return self.debugger.read_memory(address, length)

    def read_variable(self, variable):
        return self.debugger.read_variable(variable)

    def write_memory(self, address, buf, length=None):
        return self.debugger.write_memory(address, buf, length)
