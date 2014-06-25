#########################
# analbin.py by @xgusix #
#########################

import argparse
import pefile
import time
import re

#Definition of subsystem constants
IMAGE_SUBSYSTEM_UNKNOWN = "Unknown subsystem."
IMAGE_SUBSYSTEM_NATIVE = "No subsystem required (device drivers and native\
 system processes)."
IMAGE_SUBSYSTEM_WINDOWS_GUI = 'Windows graphical user interface (GUI)\
 subsystem.'
IMAGE_SUBSYSTEM_WINDOWS_CUI = 'Windows character-mode user interface (CUI)\
 subsystem.'
IMAGE_SUBSYSTEM_OS2_CUI = 'OS/2 CUI subsystem.'
IMAGE_SUBSYSTEM_POSIX_CUI = 'POSIX CUI subsystem.'
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 'Windows CE system.'
IMAGE_SUBSYSTEM_EFI_APPLICATION = 'Extensible Firmware Interface (EFI)\
 application.'
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 'EFI driver with boot services.'
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 'EFI driver with run-time services.'
IMAGE_SUBSYSTEM_EFI_ROM = 'EFI ROM image.'
IMAGE_SUBSYSTEM_XBOX = 'Xbox system.'
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 'Boot application.'

def init():
	parser = argparse.ArgumentParser(
		description='Quick analysis of PE file')

	parser.add_argument("file", nargs=1, metavar='filename',
		help='File to be analyzed.')

	args = parser.parse_args()
	return args

def getCompileDate(pe):
	ts = pe.FILE_HEADER.TimeDateStamp
	return time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(ts))

def getSubsystem(pe):
	ss = pe.OPTIONAL_HEADER.Subsystem

	res = 0

	if ss == 0:
		res = IMAGE_SUBSYSTEM_UNKNOWN
	elif ss == 1:
		res = IMAGE_SUBSYSTEM_NATIVE
	elif ss == 2:
		res = IMAGE_SUBSYSTEM_WINDOWS_GUI
	elif ss == 3:
		res = IMAGE_SUBSYSTEM_WINDOWS_CUI
	elif ss == 5:
		res = IMAGE_SUBSYSTEM_OS2_CUI
	elif ss == 7:
		res = IMAGE_SUBSYSTEM_POSIX_CUI
	elif ss == 9:
		res = IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
	elif ss == 10:
		res = IMAGE_SUBSYSTEM_EFI_APPLICATION
	elif ss == 11:
		res = IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
	elif ss == 12:
		res = IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
	elif ss == 13:
		res = IMAGE_SUBSYSTEM_EFI_ROM
	elif ss == 14:
		res = IMAGE_SUBSYSTEM_XBOX
	elif ss == 16:
		res = IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
	else:
		res = "Problem getting the PE's subsystem."

	return res

def main():
	args = init()

	print "Starting analysis..."

	if args.file:
		try:
			pe = pefile.PE(args.file[0])
		except pefile.PEFormatError as e:
			print e
			quit(1)
		except:
			print "ERROR: There was an error accessing to the file"
			quit(1)

	compile_date = getCompileDate(pe)
	print "[*] Compilation date:\n\t%s" % compile_date

	compile_date = getSubsystem(pe)
	print "[*] Subsystem:\n\t%s" % compile_date

	print "[*] Analysis of data sizes:"
	print "Name\t\tVirtual size\tRaw data size"
	rsrc_offset = 0

	for i in range(0,len(pe.sections)):
		section = pe.sections[i]
		print (section.Name + '\t' + str(section.Misc_VirtualSize) + '\t\t'+ 
			str(section.SizeOfRawData))
		if section.Name.find(".rsrc") != -1:
			rsrc_offset = section.PointerToRawData
			rsrc_size = section.SizeOfRawData
		if section.Name.find(".text") != -1:
			text_offset = section.PointerToRawData
			text_size = section.SizeOfRawData

	#Entry point out of the .text section.
	entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	if  entry_point < text_offset or entry_point > text_offset + text_size:
		print "[*] Entry point out of the .text section."

	#Try to find a PE File in the rsrc section.
	#This doesn't work if the file is encrypted

	#Retrieving rsrc section:
	rsrc = ''
	with open(args.file[0], 'rb') as fd:
			fd.seek(rsrc_offset)
			for x in (range(0,rsrc_size)):
				c = fd.read(1)
				rsrc += c

	#Searching for PE headers:
	pe_magicnumbers= [m.start() for m in re.finditer('MZ', rsrc)]
	if len(pe_magicnumbers) > 0:
		for offset in pe_magicnumbers:
			if rsrc[offset + 128: offset + 296].find("PE") != -1:
				print "[*] Possible embedded PE file in the offset: %s" % hex(
					int(offset) + rsrc_offset)
			else:
				print "[*] I couldn't find any PE file in the .rsrc section."
	else:
		print "[*] I couldn't find any PE file in the .rsrc section."


	#Import table extraction:
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		print "[*] " + entry.dll
		for imp in entry.imports:
			print '\t', hex(imp.address), imp.name

	print "Analysis finished."
if __name__ == '__main__':
	main()