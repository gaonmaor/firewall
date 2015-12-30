#!/usr/bin/python3

import mmap, time, ast, struct, socket

structs = {
    'log': 'I 3B 2I 2H i I',
    'rule': '>4B 2H 2I',
    'conn': '2I 2H I B 3x',
}            

class ConnTabEntry:
    def __init__(self, c):
        if not isinstance(c, str):
            raise Exception('bad conn init: c = {}'.format(c))
	print "len: " + repr(len(c)) + "\n"
	print "calcsize: " + repr(struct.calcsize(structs['conn'])) + "\n"
	if len(c) != struct.calcsize(structs['conn']):
	    raise Exception('bad conn init: c = {} len(c)'.format(c))

        (self.cli_ip, self.ser_ip, self.cli_port, self.ser_port,
            self.expires, self.state) = struct.unpack(structs['conn'], c)

with open('/dev/fw5_conn_tab', 'rb') as conn_tab, \
     open('/sys/class/fw5/fw5_conn_tab/conn_tab_size') as conn_tab_size_file:
     
     ent_size = struct.calcsize(structs['conn'])
     now = time.time()

     conn_tab_size = ast.literal_eval(conn_tab_size_file.readline())
     m = mmap.mmap(conn_tab.fileno(), conn_tab_size, mmap.MAP_SHARED, mmap.PROT_READ)

     for i in range(0, conn_tab_size, ent_size):
         ent = ConnTabEntry(m[i: i + ent_size])
         if ent.expires >= now:

             print "cli_ip: " + socket.inet_ntoa(struct.pack('L',socket.ntohl(ent.cli_ip))) + " cli_port: " + repr(ent.cli_port) + " ser_ip: " + socket.inet_ntoa(struct.pack('L',socket.ntohl(ent.ser_ip))) + " ser_port: " + repr(ent.ser_port) + " expires: " + repr(ent.expires) + " state: " + repr(ent.state)

     m.close

