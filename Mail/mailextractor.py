import getpass
import imaplib
import email
import re
import md5
import sha
import json
import simplejson
import urllib
import urllib2
import time
import argparse


VT_API = "Your_API_key"

def init():

	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", nargs=1, metavar='filename',
		help="File to process.")
	parser.add_argument("-o", "--output", nargs=1,
		help="Output.")
	parser.add_argument("-vt", "--virustotal", action='store_true',
		help="Skip virustotal chekings.")
	args = parser.parse_args()
	return args

def unique(seq):
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]

def get_ip_addresses(email_message):
	ip_addresses = []
	for header in email_message.items():
		ip = re.search(r'((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9])', header[1], re.I)
		if ip:
			ip=ip.group()
			ip_addresses.append(ip)
	return unique(ip_addresses)

def recursive(payload):
	for i in payload:
		if i.get_content_maintype() == "multipart":
			mail = i.get_payload()
			body = recursive(mail)
			return body
		elif i.get_content_maintype()  == "text":
			return i.get_payload()

def get_body(email_message):
	maintype = email_message.get_content_maintype()
	payload = email_message.get_payload()
	if maintype == "multipart":
		body = recursive(payload)
	elif maintype == "text":
		body = email_message.get_payload()
	return body
	
def get_links(body):
	links = []
	regex = re.compile(r'http.+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!]+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!]+')
	linksaux = regex.findall(body)
	for link in linksaux:
		if link.find(' ') == -1 and link.find('\t') == -1:
			links.append(link)

	return unique(links)

def get_attachments(email_message):
	payload = email_message.get_payload()
	attachments = []
	for section in payload:
		try:
			section.get_filename()
			if section.get_filename() != None:
				attachment = {}
				attachment['filename'] = section.get_filename()
				attachment['type'] = section.get_content_type()
				attachment['file'] = section.get_payload(decode=True)
				sha1 = sha.sha(attachment["file"]).hexdigest()
				hashmd5 = md5.new(attachment["file"]).hexdigest()
				attachment['hashmd5'] = hashmd5
				attachment['sha1'] = sha1			
				attachments.append(attachment)
		except:
			pass
	return attachments

def ip_vt(ip_address):
	ip= [ip_address]
	print "Retreiving information from VT for the IP %s..." % (ip_address)
	url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	parameters = {'ip': ip_address, 'apikey': VT_API}
	response = urllib.urlopen('%s?%s' % (url, 
		urllib.urlencode(parameters))).read()
	try:
		response_dict = json.loads(response)
		if response_dict['response_code'] == 1:
			try:
				ip.append(response_dict['detected_urls'])
			except:
				pass
		print "Done"
	except Exception, e:
		print "There was an error retriving %s data: %s" % (ip_address, e)

	return ip

def hash_vt(hash_):

	print "Retreiving information from VT for the hash %s..." % (hash_)
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {'resource': hash_, 'apikey': VT_API}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)

	response = urllib2.urlopen(req)
	try:
		response_dict = simplejson.loads(response.read())
		if response_dict['response_code'] != 0:
			h = [response_dict['positives'], response_dict['total'], 
				response_dict['scan_date']]
		else:
			h = "File not found in VT."
		# if response_dict['response_code'] == 1:
		# 	try:
		# 		ip.append(response_dict['detected_urls'])
		# 	except:
		# 		pass
		print "Done"
	except Exception, e:
		print "There was an error retreiving %s data: %s" % (hash_, e)
		h = "Error retreiving VT data."

	return h

def o_console(frm, to, cc, subject, messageID, headers, ips, 
	links, attachments, args):

	if len(frm) > 0:
		print "[*] From:"
		for sender in frm:
			print "\t%s" % (sender)

	print "[*] Receivers:"

	if len(to) > 0:
		print "\t[*] To:"
		for receiver in to:
			print "\t\t%s" % (receiver)

	if len(cc) > 0:
		print "\t[*] Cc:"
		for receiver in cc:
			print "\t\t%s" % (receiver)

	if len(messageID) > 0:
		print "[*] Message-ID:"
		for mid in messageID:
			print "\t%s" % (mid)

	if len(subject) > 0:
		print "[*] Subject:"
		for sbj in subject:
			print "\t%s" % (sbj)

	print "[*] Headers:"
	for line in headers:
		print "\t%s: %s" % (line[0], line[1])

	if len(ips) > 0:
		print "[*] IP Addresses:"
		if args.virustotal:
			for ip in ips:
				print ip
		else:
			for ip in ips:
				print "\t%s" % (ip[0])
				if len(ip) > 1:
					for i in ip[1]:
						print "\t\t%s - %d/%d - %s" % (i['url'], i['positives'],
							i['total'], i['scan_date'])

	if len(links) > 0:
		print "[*] Links:"
		for link in links:
			print "\t%s" % (link)

	if len(attachments) > 0:
		print "[*] Attachments:"
		for att in attachments:
			print "\tFile: %s" % (att["filename"])
			print "\tFile type: %s" % (att["type"])
			print "\tSHA1: %s" % (att['sha1']) 
			print "\tMD5:%s" % (att['hashmd5'])
			try:
				print "\tVT detections: %d/%d - %s" % (att['vt'][0],
					att['vt'][1], att['vt'][2])
			except:
				pass

def main():

	args = init()

	if args.file:
		try:
			email_message = email.message_from_string(open(args.file[0]).read())
		except Exception, e:
			print "There was an error opening the file %s: %s" % (args.file[0],
				e)
			quit()

	else:
		print "ERROR: You must use the option -f."
		quit()

	frm = email_message.get_all('from', [])
	to = email_message.get_all('to', [])
	cc = email_message.get_all('cc', [])
	subject = email_message.get_all('subject',[])
	messageID = email_message.get_all('message-ID', [])
	headers = email_message.items()
	ips = get_ip_addresses(email_message)
	links = get_links(get_body(email_message))
	attachments = get_attachments(email_message)
	
	vt_count = 0
	if not args.virustotal:
		ip_struct = []
		for ip in ips:
			if vt_count >= 4:
				time.sleep(30)
				vt_count = 0
			ip_struct.append(ip_vt(ip))
			vt_count += 1
		ips = ip_struct

		for att in attachments:
			if vt_count >= 4:
				time.sleep(30)
				vt_count = 0
			
			att['vt'] = hash_vt(att['sha1'])
			vt_count += 1
	
	if args.output:
		##
		## TODO
		##
		o_console(frm, to, cc, subject, messageID, headers, ips, 
			links, attachments, args)
	else:
		o_console(frm, to, cc, subject, messageID, headers, ips, 
		links, attachments, args)

if __name__ == '__main__':
	main()






