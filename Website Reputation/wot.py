import requests
import sys
import simplejson
import argparse

WOT_API_KEY = "YOUR_OWN_API_KEY!!!"

def init():
	parser = argparse.ArgumentParser(
		description='Script for returning WoT score for a bunch of domains')
	"""
		Examples of domains in file:
			example.com 		[OK]
			http://example.com 	[KO]
	"""

	parser.add_argument("file", nargs=1, metavar='filename',
		help='File with the domains\' list.')

	args = parser.parse_args()
	return args



def getScore(trust):
	res = ''	
	if trust >= 80:
		res = 'Excellent'
	elif trust >=60 and trust < 80:
		res = 'Good'
	elif trust >=40 and trust < 60:
		res = 'Unsatisfactory'
	elif trust >=20 and trust < 40:
		res = 'Poor'	
	else:
		res = 'Very Poor'
	return res

def getCategory(category):
	group = ''
	description = ''

	#Positive
	if category >= 500: 
		group = 'Positive'
		if category == 501:
			description = 'Good site'
		else:
			description = 'There was probably an error interpreting the code'

	#Child safety 
	elif category >= 400 and category <= 500: 
		if category == 401:
			group = 'Negative'
			description = 'Adult content'
		elif category == 404:
			group = 'Positive'
			description = 'Site for kids'
		else:
			group = 'Questionable'
			if category == 402: description = 'Incidental nudity'
			elif category == 403: description = 'Gruesome or shocking'
			else: description = 'There was probably an error interpreting the code'

	#Neutral
	elif category >= 300 and category <= 400:
		group = 'Neutral'
		if category == 301:
			description = 'Online tracking'
		elif category == 302:
			description = 'Alternative or controversial medicine'
		elif category == 303:
			description = 'Opinions, religion, politics'
		elif category == 304:
			description = 'Other'
		else:
			description = 'There was probably an error interpreting the code'

	#Questionable
	elif category >= 200 and category <= 300:
		group = 'Questionable'
		if category == 201:
			description = 'Misleading claims or unethical'
		elif category == 202:
			description = 'Privacy risks'
		elif category == 203:
			description = 'Suspicious'
		elif category == 204:
			description = 'Hate, discrimination'
		elif category == 205:
			description = 'Spam'
		elif category == 206:
			description = 'Potentially unwanted programs'
		elif category == 207:
			description = 'Ads / pop-ups'
		else:
			description = 'There was probably an error interpreting the code'

	#Negative
	elif category >= 100 and category <= 200:
		group = 'Negative'
		if category == 101:
			description = 'Malware or viruses'
		elif category == 102:
			description = 'Poor customer experience'
		elif category == 103:
			description = 'Phishing'
		elif category == 104:
			description = 'Scam'
		elif category == 105:
			description = 'Potentially illegal'
		else:
			description = 'There was probably an error interpreting the code'
	return group, description

def main():

	args = init()

	if args.file:
		try:
			data = open(args.file[0],'r').read()
			domains = data.replace('\n','/')+'/'
		except Exception, e:
			print('%s', e)
			quit(1)

	response = requests.get(
		"http://api.mywot.com/0.4/public_link_json2",
		params={"hosts":domains,"key":WOT_API_KEY}
		)
	json = simplejson.loads(response.content)

	for domain in json:
		print "[*] %s" % domain
		for component in json[domain]:
			if component == 'target':
				print '\tTarget: %s' % json[domain][component]
			elif component == '0':
				trust = getScore(json[domain][component][0])
				print "\tTrustworthiness: %s [%s]" % (trust,json[domain][component][1])
			elif component == '4':
				childSafety = getScore(json[domain][component][0])
				print "\tChild safety: %s [%s]" % (childSafety,json[domain][component][1])
			elif component == 'categories':
				print "\t[*] Categories:"
				for category in json[domain][component]:
					group, desc = getCategory(int(category))
					print "\t\t[%s] %s %s [%s]" % (category, group, desc, json[domain][component][category])

if __name__ == '__main__':
	main()
