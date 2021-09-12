# SQL Command to create table for CSV Results Report
sql = """
	CREATE TABLE results (
		r_id INTEGER primary key autoincrement,
		ip CHARACTER,
		hostname TEXT,
		port TEXT,
		port_protocol TEXT,
		cvss TEXT,
		severity TEXT,
		solution_Type TEXT,
		nvt_name TEXT,
		summary TEXT,
		specific_result TEXT,
		nvt_oid TEXT,
		CVEs TEXT,
		task_ID TEXT,
		task_Name TEXT,
		Time_stamp TEXT,
		result_ID TEXT,
		impact TEXT,
		solution TEXT,
		Affected_Software TEXT,
		Vulnerability_Insight TEXT,
		Vulnerability_Detection_Method TEXT,
		Product_Detection_Result TEXT,
		BIDs TEXT,
		CERTs TEXT,
		Other_References TEXT
		) """
		
# SQL Command to create table for imported Hosts with Priorities
sql_hosts = """
	CREATE TABLE IF NOT EXISTS Host_Prios (
		Priority TEXT,
		h_ip CHARACTER
		) """
# SQL Command to join both tables 
sql_join = """
	CREATE TABLE _Report 
	AS SELECT * 
	FROM results
	LEFT OUTER JOIN Host_Prios 
	On h_ip = results.ip
	;"""		

# SQL Command to modify the report table, so there are no duplicated IP columns
sql_mod = """
		CREATE TABLE Report
		AS SELECT ip, hostname, Priority, port, port_protocol, cvss, severity, solution_Type, nvt_name, summary, specific_result, nvt_oid, CVEs, impact, solution, Affected_Software, Vulnerability_Insight, Vulnerability_Detection_Method, Product_Detection_Result, BIDs, CERTs, Other_References
FROM _REPORT;"""

sql_drop1 = """ DROP TABLE _Report;"""
sql_drop2 = """ DROP TABLE Results;"""
sql_drop3 = """	DROP TABLE Host_Prios;"""

# Ich brauche Queries:
#	Anzahl unbekannter Geräte
sql_q_unknwndev = """
				SELECT COUNT(*)
				FROM Report
				WHERE Priority IS NULL 
				GROUP BY ip
				"""
#	Schwachstellen-Anzahl geordnet nach Severity
sql_q_seve = """
			SELECT severity, COUNT(*)
			FROM Report
			GROUP BY severity
			"""
			
#	Schwachstellen-Anzahl geordnet nach Solution-Type
sql_q_solty = """
			SELECT solution_Type, COUNT(*)
			FROM Report
			GROUP BY solution_Type
			"""
#	Schwachstellen mit: hoher Severity, high priorisiert
sql_q_his_hip = """
			SELECT COUNT(*)
			FROM Report
			WHERE severity = "High" AND Priority="high"
			"""
#	Schwachstellen mit: hoher Severity, high priorisiert, lösbar durch vendorfix
sql_q_his_hip_vfix = """
			SELECT COUNT(*)
			FROM Report
			WHERE severity = "High" AND Priority="high" AND solution_Type="VendorFix"
			"""

