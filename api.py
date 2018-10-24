from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, requests
from collections import OrderedDict

def rmNotes(request, hashstr):
	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
	if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
		os.remove('/opt/notes/'+scanfilemd5+'_'+hashstr+'.notes')
		res = {'ok':'notes removed'}
	else:
		res = {'error':'invalid format'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def saveNotes(request):
	if request.method == "POST":
		scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

		if re.match('^[a-f0-9]{32,32}$', request.POST['hashstr']) is not None:
			f = open('/opt/notes/'+scanfilemd5+'_'+request.POST['hashstr']+'.notes', 'w')
			f.write(request.POST['notes'])
			f.close()
			res = {'ok':'notes saved'}
	else:
		res = {'error': request.method }

	return HttpResponse(json.dumps(res), content_type="application/json")

def rmlabel(request, objtype, hashstr):
	types = {
		'host':True,
		'port':True
	}

	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
		os.remove('/opt/notes/'+scanfilemd5+'_'+hashstr+'.'+objtype+'.label')
		res = {'ok':'label removed'}
		return HttpResponse(json.dumps(res), content_type="application/json")

def label(request, objtype, label, hashstr):
	labels = {
		'Vulnerable':True,
		'Critical':True,
		'Warning':True,
		'Checked':True
	}

	types = {
		'host':True,
		'port':True
	}

	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	if label in labels and objtype in types:
		if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
			f = open('/opt/notes/'+scanfilemd5+'_'+hashstr+'.'+objtype+'.label', 'w')
			f.write(label)
			f.close()
			res = {'ok':'label set', 'label':str(label)}
			return HttpResponse(json.dumps(res), content_type="application/json")

def port_details(request, address, portid):
	r = {}
	oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
	r['out'] = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r['out'])

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		if '@addr' in i['address']:
			saddress = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					saddress = ai['@addr'] 

		if str(saddress) == address:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if p['@portid'] == portid:
					return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

def genPDF(request):
	if 'scanfile' in request.session:
		pdffile = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
		if os.path.exists('/opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf'):
			os.remove('/opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf')

		os.popen('/opt/wkhtmltox/bin/wkhtmltopdf --cookie sessionid '+request.session._session_key+' --enable-javascript --javascript-delay 6000 http://127.0.0.1:8000/view/pdf/ /opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf')
		res = {'ok':'PDF created', 'file':'/static/'+pdffile+'.pdf'}
		return HttpResponse(json.dumps(res), content_type="application/json")

def getCVE(request):
	res = {}

	if request.method == "POST":
		scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
		hostmd5 = hashlib.md5(str(request.POST['host']).encode('utf-8')).hexdigest()
		portmd5 = hashlib.md5(str(request.POST['port']).encode('utf-8')).hexdigest()

		# request.POST['host']
		r = requests.get('http://cve.circl.lu/api/cvefor/'+request.POST['cpe'])

		if request.POST['host'] not in res:
			res[request.POST['host']] = {}

		cvejson = r.json()

		if type(cvejson) is list and len(cvejson) > 0:
			res[request.POST['host']][request.POST['port']] = cvejson[0]
			f = open('/opt/notes/'+scanfilemd5+'_'+hostmd5+'.'+request.POST['port']+'.cve', 'w')
			f.write(json.dumps(cvejson))
			f.close()

		return HttpResponse(json.dumps(res), content_type="application/json")
