import sqlite3
import csv
import os
import sys 
import db_helper
import sendmail
#-------------CONFIGURATIONS------------
DB_NAME = 'Results.db'
#-------------DEFINITIONS---------------
#read glboal conf
def read_globalconf():
	d = os.getcwd()
	d1 = os.path.abspath(os.path.join(d, os.pardir))
	fname = os.path.join(d1,"glob.cfg")
	contents = open(fname, "r").read()
	config = eval(contents)
	HOST_FILENAME = config['hostname_path']
	return HOST_FILENAME

#---------------------------------------
# Write Hosts-Priorities.txt into DB
def write_host_prios(c, HOST_FILENAME):
	try:
		d = os.getcwd()
		d1 = os.path.abspath(os.path.join(d, os.pardir)) + "/" + HOST_FILENAME
		with open(d1, 'r') as hst:
			hst_rd = csv.DictReader(hst,delimiter='\t')
			to_db_1 = [(i['Priority'], i['IP']) for i in hst_rd]

		c.executemany("INSERT INTO Host_Prios VALUES (?, ?);", to_db_1)

	except Exception as e:
		print(e)
		quit()
#---------------------------------------
# Write Report-Results.csv into DB
def write_results(c , CSV_FILENAME):
	try:
		
		d = os.getcwd()
		d1 = os.path.abspath(os.path.join(d, "csv_results" + "/" + CSV_FILENAME))
		path = d1
		print("PATH: " + path)
		with open(path,'r') as fin: 
			# csv.DictReader uses first line in file for column headings by default
			dr = csv.DictReader(fin) # comma is default delimiter
			to_db = [(i['IP'], i['Hostname'], i['Port'], i['Port Protocol'], i['CVSS'], i['Severity'], i['Solution Type'], i['NVT Name'], i['Summary'], i['Specific Result'], i['NVT OID'] , i['CVEs'], i['Task ID'], i['Task Name'], i['Timestamp'], i['Result ID'], i['Impact'], i['Solution'], i['Affected Software/OS'], i['Vulnerability Insight'], i['Vulnerability Detection Method'], i['Product Detection Result'], i['BIDs'], i['CERTs'], i['Other References']) for i in dr]

		c.executemany("INSERT OR REPLACE INTO results VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);", to_db)
	except Exception as e:
		print(e)
		quit()
#---------------------------------------
# Remove Database-File and CSV Reports
def cleanup():

	try:
		os.remove(DB_NAME)
	except Exception as e:
		pass
	mydir = os.getcwd()
	mydir = os.path.join(mydir,"csv_results/")
	
	for f in os.listdir(mydir):
		if not f.endswith(".csv"):
		    continue
		os.remove(os.path.join(mydir, f))
	try:
		mydir = os.getcwd()
		helpfile = os.path.abspath(os.path.join(mydir, "csv_results" + "/" + "last_report_names"))
		os.remove(helpfile)
	except (OSError, IOError) as e:	
		print("Could not remove 'last_report_names'\n" + e)
		quit()

# Execute SQLite Queries and generate mailtext		
def exe_sql_q(c):
	c.execute(db_helper.sql_q_seve)
	q_sev = c.fetchall()
	#print(q_sev)
	#print(list(y for x, y in q_sev if x  == "High"))

	c_high = list(y for x, y in q_sev if x  == "High")
	c_med = list(y for x, y in q_sev if x  == "Medium")
	c_low = list(y for x, y in q_sev if x  == "Low")
	c_log = list(y for x, y in q_sev if x  == "Log")

	c.execute(db_helper.sql_q_solty)
	q_solty = c.fetchall()
	c_vfix = list(y for x, y in q_solty if x  == "Vendor Fix")
	c_mit = list(y for x, y in q_solty if x  == "Mitigation")
	c_woa = c_vfix = list(y for x, y in q_solty if x  == "Workaround")
	c_wnf = c_vfix = list(y for x, y in q_solty if x  == "WillNotFix")
	c_nos = c_vfix = list(y for x, y in q_solty if x  == "")

	c.execute(db_helper.sql_q_his_hip)
	q_his_hip = c.fetchone()[0]
	
	c.execute(db_helper.sql_q_his_hip_vfix)
	q_his_hip_vfix = c.fetchone()[0]
	
	mail_text = "Number of Vulnerabilities with HIGH Severity:\t\t\t" + str(c_high[0]) + "\n" + "Number of Vulnerabilities with MEDIUM Severity:\t\t\t" + str(c_med[0]) + "\n" + "Number of Vulnerabilities with LOW Severity:\t\t\t" + str(c_low[0]) + "\n" + "Number of Vulnerabilities with LOG (0.0) Severity:\t\t" + str(c_log[0]) + "\n" +  "-----------------------------------------------------------------------------" + "\n" + "Number of Vulnerabilities with Solution Type 'Vendor Fix':\t" + str(c_vfix[0]) + "\n" + "Number of Vulnerabilities with Solution Type 'Mitigation':\t" + str(c_mit[0]) + "\n" + "Number of Vulnerabilities with Solution Type 'Workaround':\t" + str(c_woa[0]) + "\n" + "Number of Vulnerabilities with Solution Type 'Will Not Fix':\t" + str(c_wnf[0] + c_nos[0]) + "\n" + "-----------------------------------------------------------------------------" + "\n" + "Number of Vulnerabilities with HIGH severity on high priorized hosts: " + str(q_his_hip) + "\n" + "Number of Vulnerabilities with HIGH severity on high priorized hosts, solvabe with VendorFix: " + str(q_his_hip) + "\n" + "-----------------------------------------------------------------------------"

	return mail_text	
#---------------------------------------------------
#---------------MAIN FUNCTION ----------------------
def main():
	try:
		HOST_FILENAME = read_globalconf()
		d = os.getcwd()
		helpfile = os.path.abspath(os.path.join(d, "csv_results" + "/" + "last_report_names"))
		with open(helpfile,'r') as f:
			lines = [line.rstrip() for line in f]		
		try:
			os.remove(DB_NAME)
		except (OSError, IOError) as e:	
			pass	
					
		for csv_filename in lines:

			# create new Database and cursor
			conn = sqlite3.connect(DB_NAME) 
			c = conn.cursor()			

			# Create Table Host and Results
			c.execute(db_helper.sql)
			c.execute(db_helper.sql_hosts)

			write_host_prios(c,HOST_FILENAME)
			write_results(c, csv_filename)

			# Join Databases to create "Host_Priority" column for every Result
			c.execute(db_helper.sql_join)
			# Create New modified Table without redundant columns
			c.execute(db_helper.sql_mod)
			# Drop unecessary tables
			c.execute(db_helper.sql_drop1)
			c.execute(db_helper.sql_drop2)
			# Query Database
			c.execute(db_helper.sql_q_seve)

			# Export data into CSV file
			c.execute("select * from Report")
			REPORT_FILENAME = os.path.dirname(os.path.dirname(os.path.abspath("REPORTS"))) + "/REPORTS/" + csv_filename 
			print("Stored Report under:\n" + REPORT_FILENAME)
			with open(REPORT_FILENAME, "w") as csv_file:
				csv_writer = csv.writer(csv_file, delimiter=",")
				csv_writer.writerow([i[0] for i in c.description])
				csv_writer.writerows(c)
			# run queries to create mailtext
			mail_text = exe_sql_q(c)
			conn.commit()
			conn.close()
			os.remove(DB_NAME)
			print("----------------------------------------------")
			# sendmail
			sendmail.main(REPORT_FILENAME, mail_text)
			
		cleanup()
	
	except Exception as e:
		print(e)
		print("Exiting.")
		quit()
