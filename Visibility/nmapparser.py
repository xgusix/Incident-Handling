import argparse
from BeautifulSoup import BeautifulSoup

def init():      
    parser = argparse.ArgumentParser(
    	description = 'Script that parses the results of the nmap command: \
    	\"nmap -sT -sU -v -n -oX filename.xml networkrange\" used in order to \
    	check the visibility of a host in a given network')
    parser.add_argument("file", nargs=1, metavar='filename', 
    	help="Nmap .xml output.")
    parser.add_argument("-c", "--csv", nargs=1, metavar='file.csv', 
    	help="Dump output in csv format. <-c filename.csv")

    args = parser.parse_args()

    return args


def main():

	args = init()

	xml = BeautifulSoup(open(args.file[0],'r').read())
	print "Analyzing results of the nmap query: %s ..." % xml.nmaprun['args']
	if args.csv:
		try:
			fd = open(args.csv[0], 'w')
			fd.write("Analyzing results of the nmap query: %s ...\n" % xml.nmaprun['args'])
			for host in xml.nmaprun.findAll('host'):
				if host.status['state'] != "down":
					addr = host.address['addr']
					if not host.findAll('ports'):
						fd.write('%s,No ports info\n' % addr) 
						continue
					for ports in host.findAll('ports'):
						for port in ports.findAll('port'):
							fd.write('%s,%s,%s,%s\n' % (addr, port['portid'],
								port['protocol'],port.state['state']))
			fd.close()

		except Exception, e:
			print "There was an error writing the file %s: \n%s" % (args.csv[0],
				e)
		
	else:
		for host in xml.nmaprun.findAll('host'):
			if host.status['state'] != "down":
				addr = host.address['addr']
				print '[*]' + addr
				for ports in host.findAll('ports'):
					for port in ports.findAll('port'):
						print '\t%s/%s\t%s' % (port['portid'],port['protocol'],
							port.state['state'])
	print "Analysis done"

if __name__ == '__main__':
        main()



