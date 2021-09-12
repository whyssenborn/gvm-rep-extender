import sys
import base64
import os.path
from argparse import Namespace
import gvmtools.config
import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection
from gvm.transforms import EtreeCheckCommandTransform
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError
from gvm.xml import pretty_print
from datetime import datetime

##########################  CONFIGURATIONS	###########################

# Socketpath 
path='/var/run/gvmd.sock'
# Path for tasknames to include in report (default taskname_path='/usr/share/reports/tasknames.txt')

# Setup connection via Socket
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()

##########################  DEFINITIONS     ############################

#read glboal conf
def read_globalconf():
	d = os.getcwd()
	d1 = os.path.abspath(os.path.join(d, os.pardir))
	fname = os.path.join(d1,"glob.cfg")
	contents = open(fname, "r").read()
	config = eval(contents)
	username = config['username']
	password = config['password']
	taskname_path = config['taskname_path']
	
	return username,password,taskname_path

#------------------------	
#get report_format_id for "csv-results" format
def get_repfid():
	repfid = []
	repfid = gmp.get_report_formats(filter_string="CSV Results")
	for fids in repfid.xpath('report_format'):
			t_fid = fids.get('id')
			name = fids.find('name').text
			if name == "CSV Results":
				fid = t_fid
	return fid

#------------------------
# get latest reports from all tasks
def get_last_reports():

		tasks = []
		tasks = gmp.get_tasks(filter_string='rows=-1')

		last_rep_dic = {}

		# XML Parsing, store taskname and latest report_id in dictionary

		for task in tasks.xpath('task'):
			taskname = task.find('name').text
			last_rep = task.find('last_report')
			if last_rep is not None:
				report = last_rep.find('report')
				if report is not None:
					last_rep_dic[taskname] = report.get('id')
		return last_rep_dic

#------------------------
# Read File with tasknames to include for report	

def open_taskname_file(taskname_path):
	imp_names =  []

	with open(taskname_path) as reader:
		line = reader.readline()
		while line != '':
			imp_names.append(line.split("\n")[0])
			line = reader.readline()	
		reader.close()
	return imp_names

#------------------------
# Compare Tasknames between the content of the given tasknames-file and GVM

def compare_tasknames(resp,p):
	report_names = []
	report_ids = []
	for y in p:
		if y in resp:
			report_names.append(y)
	print("Found the following tasks in GVM and your configured tasklist:") 
	print(report_names)
	print("-------------------------------------------------------------------------------------")
	
	for z in report_names:
		report_ids.append(resp.get(z))
	return report_ids
	
#------------------------
# Helper to create a String out of a list. Necessary for running the gvm-script command

def listToString(s):
	str1 = ""
	for ele in s:
		str1 += ele
		str1 += " "
	return str1

#------------------------
# Helper to check the given Input from CLI
def check_arg(*args):

	if len(args) > 1:
		print("-------------------------------------------------------------------------------------")
		print("Too many arguments. Please specify ONE name for the report-file. Script will exit.")
		print("-------------------------------------------------------------------------------------")
		quit()
	if len(args) == 0:
		container_task_name = "Vulnerabilty-Report"
		print("-------------------------------------------------------------------------------------")
		print("No name for created report given. Please specify ONE name for the report-file. Script will exit.")
		print("-------------------------------------------------------------------------------------")
		quit()
		
	if len(args) == 1:
		container_task_name = args[0]
		print("-------------------------------------------------------------------------------------")
		print("Saving the report as: " + '"' + datetime.today().strftime('%Y_%m_%d_') + container_task_name + '.csv"')
		print("-------------------------------------------------------------------------------------")
		return container_task_name

#------------------------
def find_reports(container_task_name):
	# Get Reports from GVM
	reps = gmp.get_reports()
		
	# Find the new created container-task-report-ID
	for tasks in reps.findall("report"):
		tmp_id = tasks.get('id')
		for report in tasks.xpath("task"):
			ct_rep_name = str(report.find('name').text)
			if container_task_name == ct_rep_name:
				ct_rep_id = tmp_id
				ct_task_id = report.get('id')
	return(ct_rep_id, ct_task_id)

#------------------------
# Get CSV-Report from GVM. It is provided in Base64 and therefore needs decoding.
def base64_downloader(ct_rep_id,repfid):
	dl_rep = gmp.get_report(ct_rep_id, report_format_id=repfid, ignore_pagination=True)
	# parse b64-tring out of response
	b64 = dl_rep
	b64 = ET.tostring(b64, encoding='utf-8', method='xml')
	b64 = b64.decode().split('</report>')
	b64 = b64[0].split('</report_format>')
	message_bytes = base64.b64decode(b64[1])
	message = message_bytes.decode('ascii')
	return message

#------------------------
# Write the downloaded report to the specified name
def report_to_file(message, report_name):

	d = os.getcwd()
	reportname = datetime.today().strftime('%Y_%m_%d_') + report_name + ".csv"

	# write Name of report in file for later usage via database
	helpfile = os.path.abspath(os.path.join(d, "csv_results" + "/" + "last_report_names"))
	f = open(helpfile,"a")
	f.write(reportname + "\n")
	f.close()

	helpfile = os.path.abspath(os.path.join(d, "csv_results" + "/" + reportname))	
	# write Report in CSV File 
	f = open(helpfile, "w")	
	f.write(message)
	f.close()

#------------------------
# Starts the Script 
def start(*arg) -> None:
	
	container_task_name = check_arg(*arg)
	report_name = container_task_name
	username, password, taskname_path = read_globalconf()
		
	global gmp
	try:
		# Connecto to greenbone 		
		with Gmp(connection=connection, transform = transform) as gmp:
			gmp.authenticate(username, password)
			resp = get_last_reports()
		repfid = get_repfid()
		# Get tasknames out of imported file (name for the file = taskname_path)	
		p = open_taskname_file(taskname_path)	
		q = compare_tasknames(resp,p)
			
		# r contains the latest report-IDs, as argument for the gvm-script command
		r = listToString(q)

		# command to run gvm-script (via local socket)
		# creates a container task and imports the latest reports from the specified tasknames
		command = "/usr/local/bin/gvm-script --gmp-username " + '"' + username + '"' + " --gmp-password " + '"' +  password + '" socket'  + " /usr/share/reports/scripts/combine-reports.gmp.py " + " " + r + " 'name' " + '"' + container_task_name + '"'

		# run gvm-script command as gvm user
		try:
			os.system('su gvm -c "' + command + '"')
		except Exception as ex:
			print(ex)
		
		# find the report-id and task-id for the created container task
		ct_rep_id, ct_task_id = find_reports(container_task_name)
		
		# download report (as csv, which is provided as b64-String)
		message = base64_downloader(ct_rep_id, repfid)
		
		# Write Report to file. Filename contains the date.
		report_to_file(message, report_name)
		
		# delete the containertask, to prevent filling up the GVM
		gmp.delete_task(ct_task_id, ultimate=True)
		# disconnect from GVM
		gmp.disconnect()	
			
	except GvmError as e:
		print('An error occured', e, file=sys.stderr)


######################## RUN THE SCRIPT ################################
if __name__ == "__main__":
	# calls start function with the entered CLI-Arguments
	arg = sys.argv[1:]
	start(*arg)
