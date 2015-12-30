#!/usr/bin/python3

import mmap, ast, struct, socket

structs = {
    'log': 'I 3B 2I 2H i I',
    'rule': '>4B 2H 2I',
    'conn': '2I 2H I B 3x',
}

class Rule:
    def __init__(self, r):
        
        (self.protocol, self.src_mask, self.dst_mask, self.action,
            self.src_port, self.dst_port, self.src_ip,
            self.dst_ip) = struct.unpack(structs['rule'], r)

with open('/dev/fw5_rules', 'r+b') as rule_base, \
    open('/sys/class/fw5/fw5_rules/rules_size') as rule_base_size_file:

    rule_base_size = ast.literal_eval(rule_base_size_file.readline())
    r = mmap.mmap(rule_base.fileno(), rule_base_size)
    i = 0
    print "# prot  s_msk\td_msk\tACT\ts_prt\td_prt\t\ts_ip\t\td_ip\n"
    while ord(r[i * 16]) != 255:
        rule = Rule(r[i * 16: (i + 1) * 16])
        print repr(rule.protocol) + "\t" + repr(rule.src_mask) + "\t" + repr(rule.dst_mask) + "\t" + repr(rule.action) + "\t" + repr(rule.src_port) + "\t" + repr(rule.dst_port) + "\t\t" + repr(socket.htonl(rule.src_ip)) + "\t\t" + repr(socket.htonl(rule.dst_ip))
        i = i + 1
    print "255	0	0	0	0	0		0			0"
    r.close()


