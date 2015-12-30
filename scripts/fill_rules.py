#!/usr/bin/python2

import sys, struct, mmap

struct_rule = '4B2H2I' # 4 unsigned bytes, 2 unsigned short, 2 unsigned int
#rule_t_size = struct.calcsize(struct_rule)
rule_t_size = 16

def load_rules(rules_file):
	fi = open(rules_file)
	fo = open('/dev/fw5_rules', 'r+b')
	m = mmap.mmap(fo.fileno(), 4096)

	i = 0
	for l in fi.readlines():
		if len(l) == 0 or l[0] == '#' or l.split() == []:
			pass
			# print(l, 'is a comment line, ignoring')
		else:
			try:
				lst = l.split()
				m[i * rule_t_size: (i + 1) * rule_t_size] = struct.pack(struct_rule, int(lst[0]), int(lst[1]), int(lst[2]), int(lst[3]), int(lst[4]), int(lst[5]), int(lst[6]), int(lst[7]))
				i += 1
			except:
				print('didn\'t understand: ' + l)

	m[i * rule_t_size] = b'\xff' 
	m[(i * rule_t_size) + 1: (i + 1) * rule_t_size] = (b'\x00' * (rule_t_size - 1))


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('usage: {} <RULES_FILE>')
		sys.exit(1)
		
	load_rules(sys.argv[1])	
