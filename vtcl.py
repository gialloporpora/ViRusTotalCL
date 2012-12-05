# Download the postFile.py file from ActiveState: http://code.activestate.com/recipes/146306/
# It is used to make the POST query to VirusTotal site to upload the file
import postfile

# You can install simplejson using pip: pip install simplejson
import simplejson
import argparse
from os import path
import urllib
import urllib2
from sys import exit


# Please insert your API Key. You can find it in your VirusTotal profile, you need to register to site to have one
my_api_key = "YOUR_API_KEY_HERE"


class jsonFile(object):
	def __init__(self, name):
		self._name = name
		if path.exists(name):
			f = open(name, "r")
			self._list = simplejson.load(f)
			f.close()
		else:
			self._list = []
	def append(self, el):
		if not(self.has_entry(el)):
			self._list.append(el)

	def  has_entry(self, el):
		return el in self._list

	def remove(self, el):
		self._list.remove(el)

	def save(self):
		f = open(self._name, "w")
		simplejson.dump(self._list, f)
		f.close()
		


def getID(file):
	import hashlib
	f = open(file, "rb")
	s = f.read()
	f.close()
	return hashlib.sha256(s).hexdigest()
	
	
def postToVT(file):
	global my_api_key
	host = "www.virustotal.com"
	selector = "https://www.virustotal.com/vtapi/v2/file/scan"
	fields = [("apikey", my_api_key)]
	filename = path.basename(file)
	file_to_send = open(file, "rb").read()
	files = [("file", filename, file_to_send)]
	json = postfile.post_multipart(host, selector, fields, files)
	return simplejson.loads(json)
def prettyReport(scanresult):
	s = ""
	s += "Scan ID: %(scan_id)s\nResource: %(resource)s\nDate: %(scan_date)s\nPermalink: %(permalink)s\nSha256: %(sha256)s\nDetection Ratio: %(positives)s of %(total)s\n\n" %(scanresult)
	scans = scanresult["scans"]
	l = []
	for i in scans:
		l.append({"version" : "%s %s" %(i, scans[i]["version"]), "update" : scans[i]["update"], "detected" : scans[i]["detected"], "result" : scans[i]["result"]})
	good = [i for i in l if i["detected"]]
	bad = [i for i in l if not(i["detected"])]
	good.sort(lambda x, y: cmp(x["version"].lower(), y["version"].lower()))
	bad.sort(lambda x, y: cmp(x["version"].lower(), y["version"].lower()))
	good.extend(bad)
	l = good
	# Now list is sorted
	maxlength = 0
	for i in l:
		if len(i["version"]) > maxlength: maxlength = len(i["version"])
	for i in l:
		i["version"] = i["version"].ljust(maxlength)
		i["detected"] = str(i["detected"]).ljust(6)
		s+="%(version)s %(detected)s  %(update)s %(result)s\n" %i
	s+="\n\n"
	return s
	
	
def rescan(id):
	""" Rescan a file, it accepts the SHA256 hash of the file as argument """
	global my_api_key
	url = "https://www.virustotal.com/vtapi/v2/file/rescan"
	parameters = {"resource": id, "apikey": my_api_key}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	return simplejson.loads(json)

def getReport(id):
	""" Return the  report of a specified file, ID is the SHA256 hash of the file """
	global my_api_key
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": id, "apikey": my_api_key}
	data = urllib.urlencode(parameters)	
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = simplejson.loads(response.read())
	return json
if __name__ == '__main__':
	queue = jsonFile("queue.json")
	parser = argparse.ArgumentParser(description="Commandline VirusTotal utility.", version="0.1")
	parser.add_argument('filename',
	help= "The file to send to VirusTotal for scanning.")
	parser.add_argument("-r", "--refresh", action="store_true",
	help="Force rescan of the file.")
	parser.add_argument("-l", "--log", action="store_true",
	help="Save the report as a .LOG file.")
	args = parser.parse_args()
	hashid = getID(args.filename)
	if args.refresh: 
		resp = rescan(hashid)
		if resp["response_code"]==1:
			print "Successfully requested a rescan of the file. Try again later..."
			queue.append(hashid)
			queue.save()
		else: print "Somethings goes wrong, sorry try again later."
		exit(0)
			
	resp1 = getReport(hashid)
	if resp1["response_code"]==1:
		repoutput = prettyReport(resp1)
		print repoutput
		if args.log:
			filename = "%s.log" %(args.filename)
			f = open(filename, "w")
			f.write(repoutput)
			f.close()
	else:
		if queue.has_entry(hashid): print "please wait a moment... You have already submitted this file."
		else:
			# The file is not yet been uploaded, upload it for the first time
			resp2 = postToVT(args.filename)
			print "File has been uploaded, please wait some minutes, the link of your scan is:"
			print resp2["permalink"]
			queue.append(hashid)
			queue.save()