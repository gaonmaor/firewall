#!/usr/bin/python3

import mmap, time, ast, struct, socket

structs = {
    'log': 'I 3B 2I 2H i I',
    'rule': '>4B 2H 2I',
    'conn': '2I 2H I B 3x',
}            

class Log:
    def __init__(self, l):
        if not isinstance(l, str):
            raise Exception('bad log init: l = {}'.format(l))
	#print "len: " + repr(len(l)) + " calcsize: " + repr(struct.calcsize(structs['log']))
	if len(l) != struct.calcsize(structs['log']):
            raise Exception('bad log init: l = {} calcsize'.format(l))

        (self.time, self.prot, self.action, self.hooknum,
            self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.reason, self.count) = struct.unpack(structs['log'], l)

with open('/dev/fw5_log', 'rb') as log, \
     open('/sys/class/fw5/fw5_log/log_size') as log_size_file:
     log_size = ast.literal_eval(log_size_file.readline())
     l = mmap.mmap(log.fileno(), log_size, mmap.MAP_SHARED, mmap.PROT_READ)
     i = 0
     log = Log(l[i * 28: (i + 1) * 28])
     print "log_size: " + repr(log_size) + " prot: " + repr(ord(l[i * 28 + 4])) + "\n"
     while ord(l[i * 28 + 4]):
         log = Log(l[i * 28: (i + 1) * 28])
         i += 1
         print repr(i) + "# tm: " + repr(log.time) + " pr: " + repr(log.prot) + " ac: " + repr(log.action) + " hk: " + repr(log.hooknum) + " sa: " + socket.inet_ntoa(struct.pack('L',socket.ntohl(log.src_ip))) + " sp: " + repr(log.src_port) + " da: " + socket.inet_ntoa(struct.pack('L',socket.ntohl(log.dst_ip))) + " dp: " + repr(log.dst_port) + " rs: " + repr(log.reason) + " ct: " + repr(log.count)

     l.close
