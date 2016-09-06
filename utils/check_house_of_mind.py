from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

class check_house_of_mind(gdb.Command):
    "print and help validate a house of mind layout"

    def __init__(self):
        super(check_house_of_mind, self).__init__("check_house_of_mind",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        """
        Specify the house of mind method and chunk address (p=mem2chunk(mem)):
        check_house_of_mind method=unsortedbin p=0x12345678
        check_house_of_mind method=fastbin p=0x12345678
        """

        if arg.find("method") == -1:
            print("Please specify the House of Mind method to use:")
            print("house_of_mind method={unsortedbin, fastbin}")
            return
        elif arg.find("p") == -1:
            print("Please specify the chunk address to use:")
            print("house_of_mind p=0x12345678")
            return
        else:
            arg = arg.split()
            for item in arg:
                if item.find("method") != -1:
                    if len(item) < 8:
                        print_error("Malformed method parameter")
                        print_error("Please specify the House of Mind method to use:")
                        print_error("house_of_mind method={unsortedbin, fastbin}")
                        return
                    else:
                        method = item[7:]
                if item.find("p") != -1:
                    if len(item) < 11:
                        print_error("Malformed chunk parameter")
                        print_error("Please specify the chunk address to use:")
                        print_error("house_of_mind p=0x12345678")
                        return
                    else:
                        p = int(item[2:],16)

        sys.stdout.write(c_title)
        print("=============================== House of Mind ==================================\n")
        sys.stdout.write(c_none)

        if method.find("unsorted") != -1:
            self.unsorted_bin_method(p)
        elif method.find("fast") != -1:
            self.fast_bin_method(p)

    def unsorted_bin_method(self, p):
        p = malloc_chunk(addr=p, inuse=True, read_data=False)

        print(c_none + "Checking chunk p")
        print(c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none)

        if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
            print(" [*] size does not wrap")
        else:
            print_error("p > -size")
            return

        if chunksize(p) >= MINSIZE:
            print(" [*] size is > minimum chunk size")
        else:
            print_error("chunksize(p) < MINSIZE")
            return

        if chunksize(p) > get_max_fast():
            print(" [*] size is not in fastbin range")
        else:
            print_error("size is in fastbin range")
            return

        if not chunk_is_mmapped(p):
            print(" [*] is_mmapped bit is not set")
        else:
            print_error("IS_MMAPPED bit is set")
            return

        if prev_inuse(p):
            print(" [*] prev_inuse bit is set")
        else:
            print_error("PREV_INUSE bit is not set.")
            print_error("This will trigger backward consolidation.")

        if chunk_non_main_arena(p):
            print(" [*] non_main_arena flag is set")
        else:
            print_error("p's non_main_arena flag is NOT set")
            return

        print(c_none + "\nChecking struct heap_info")
        print(c_none + " [*] struct heap_info = " \
                + c_value + "0x%x" % heap_for_ptr(p.address))

        inferior = get_inferior()
        if inferior == -1:
            return None

        try:
            mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
            if SIZE_SZ == 4:
                ar_ptr = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                ar_ptr = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print_error("Invalid heap_info address 0x{0:x}".format(heap_for_ptr(p.address)))
            return

        print(c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr)
        print(c_none + "\nChecking struct malloc_state")

        #test malloc_state address
        try:
            mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
        except RuntimeError:
            print_error("Invalid malloc_state address 0x{0:x}".format(ar_ptr))
            return

        av = malloc_state(ar_ptr)

        if av.mutex == 0:
            print(c_none + " [*] av->mutex is zero")
        else:
            print_error("av->mutex is not zero")
            return

        if p.address != av.top:
            print(c_none + " [*] p is not the top chunk")
        else:
            print_error("p is the top chunk")
            return

        if noncontiguous(av):
            print(c_none + " [*] noncontiguous_bit is set")
        elif contiguous(av):
            print_error("noncontiguous_bit is NOT set in av->flags")
            return

        print(" [*] bck = &av->bins[0] = " + c_value + "0x%x" % (ar_ptr+0x38))

        if SIZE_SZ == 4:
            print(c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 8) = ")
        elif SIZE_SZ == 8:
            print(c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 16) = ")

        fwd = inferior.read_memory(ar_ptr + 0x38 + 2*SIZE_SZ, SIZE_SZ)
        if SIZE_SZ == 4:
            fwd = struct.unpack("<I", fwd)[0]
        elif SIZE_SZ == 8:
            fwd = struct.unpack("<Q", fwd)[0]
        print(c_value + "0x%x" % fwd)

        if fwd != (ar_ptr+0x38):
            print_error("fwd->bk != bck")
            print_error("This will prevent this attack on glibc 2.11+")

        print(c_none + "\nChecking following chunks")
        nextchunk = chunk_at_offset(p, chunksize(p))

        if prev_inuse(nextchunk):
            print(c_none + " [*] prev_inuse of the next chunk is set")
        else:
            print_error("PREV_INUSE bit of the next chunk is not set")
            return

        if chunksize(nextchunk) > 2*SIZE_SZ:
            print(c_none + " [*] nextchunk size is > minimum size")
        else:
            print_error("nextchunk size ({0}) < {1}".format(chunksize(nextchunk),2*SIZE_SZ))
            return

        if chunksize(nextchunk) < av.system_mem:
            print(c_none + " [*] nextchunk size is < av->system_mem")
        else:
            print_error("nextchunk size (0x{0:x}) > av->system_mem".format(chunksize(nextchunk)))
            return

        if nextchunk.address != av.top:
            print(c_none + " [*] nextchunk != av->top")
        else:
            print_error("nextchunk is av->top")
            return

        if inuse_bit_at_offset(nextchunk, chunksize(nextchunk)):
            print(c_none + " [*] prev_inuse bit set on chunk after nextchunk")
        else:
            print_error("PREV_INUSE bit of chunk after nextchunk is not set")
            return

        print(c_header + "\np (0x%x) will be written to fwd->bk (0x%x)" \
                % (p.address, fwd+0xC) + c_none)

    def fast_bin_method(self, p):
        p = malloc_chunk(addr=p, inuse=True, read_data=False)

        print(c_none + "Checking chunk p")
        print(c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none)

        if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
            print(" [*] size does not wrap")
        else:
            print_error("p > -size")
            return

        if chunksize(p) >= MINSIZE:
            print(" [*] size is >= minimum chunk size")
        else:
            print_error("chunksize(p) < MINSIZE")
            return

        if chunksize(p) < get_max_fast():
            print(" [*] size is in fastbin range")
        else:
            print_error("size is not in fastbin range")
            return

        if chunk_non_main_arena(p):
            print(" [*] non_main_arena flag is set")
        else:
            print_error("p's non_main_arena flag is NOT set")
            return

        if prev_inuse(p):
            print(" [*] prev_inuse bit is set")
        else:
            print_error("PREV_INUSE bit is not set")
            print_error("This will trigger backward consolidation.")

        print(c_none + "\nChecking struct heap_info")
        print(c_none + " [*] struct heap_info = " \
                + c_value + "0x%x" % heap_for_ptr(p.address))

        inferior = get_inferior()
        if inferior == -1:
            return None

        try:
            mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
            if SIZE_SZ == 4:
                ar_ptr = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                ar_ptr = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print_error("Invalid heap_info address 0x{0:x}".format(heap_for_ptr(p.address)))
            return

        print(c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr)
        print(c_none + "\nChecking struct malloc_state")

        #test malloc_state address
        try:
            mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
        except RuntimeError:
            print_error("Invalid malloc_state address 0x{0:x}".format(ar_ptr))
            return

        av = malloc_state(ar_ptr)

        if av.mutex == 0:
            print(c_none + " [*] av->mutex is zero")
        else:
            print_error("av->mutex is not zero")
            return

        print(c_none + " [*] av->system_mem is 0x%x" % av.system_mem)

        print(c_none + "\nChecking following chunk")
        nextchunk = chunk_at_offset(p, chunksize(p))
        print(" [*] nextchunk = " + c_value + "0x%x" % nextchunk.address)

        if nextchunk.size > 2*SIZE_SZ:
            print(c_none + " [*] nextchunk size is > 2*SIZE_SZ")
        else:
            print_error("nextchunk size is <= 2*SIZE_SZ")
            return

        if chunksize(nextchunk) < av.system_mem:
            print(c_none + " [*] nextchunk size is < av->system_mem")
        else:
            print_error("nextchunk size is >= av->system_mem")
            return

        fb = ar_ptr + (2*SIZE_SZ) + (fastbin_index(p.size)*SIZE_SZ)
        print(c_header + "\np (0x%x) will be written to fb (0x%x)" \
                % (p.address, fb) + c_none)

# register command with gdb
# check_house_of_mind()
