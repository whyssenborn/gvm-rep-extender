import smtplib
import os
from os.path import basename
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication

# Subject-Line for Mail
subject = 'Vulnerability Scan Results'

# Festlegung Mail Sender und Empfänger
#filename = "NEW_REPORT.csv"

def read_globalconf():
	d = os.getcwd()
	d1 = os.path.abspath(os.path.join(d, os.pardir))
	fname = os.path.join(d1,"glob.cfg")
	contents = open(fname, "r").read()
	config = eval(contents)
	smtp_username = config['smtp_username'] # MAILFROM, user
	smtp_password = config['smtp_password'] # pwd
	#taskname_path = config['taskname_path']
	smtp_server = config['smtp_server'] #
	smtp_port = config['smtp_port']
	rcpt_to = config['rcpt_to']
	return smtp_username, smtp_password, smtp_server, smtp_port, rcpt_to


def create_att_mail(filename):
	# Öffne Anhang und lese ihn in Variable attachement ein
	with open(filename, 'r') as f:
		attachement = MIMEApplication(f.read(), Name=basename(filename))
		attachement['Content-Disposition'] = 'attachement; filename="{}"'.format(basename(filename))

	# Hänge Anhang an Nachricht
	msg.attach(attachement)
	return msg

def send_mail(msg,user,pwd,smtp_server,smtp_port,mail_from,rcpt_to):
	# Anmeldung am Mailserver, Abschicken der Mail, Trennung der Verbindung
	with smtplib.SMTP(smtp_server,smtp_port) as server:
		server.ehlo()
		server.starttls()
		server.ehlo()
		server.login(user,pwd)
		server.send_message(msg, from_addr=mail_from, to_addrs=rcpt_to)
		server.quit()

def main(*argv):
	filename = argv[0]
	
	#print(read_globalconf())
	user, pwd, smtp_server, smtp_port, rcpt_to = read_globalconf()

	mail_from = user
	print("FILENAME: " + filename)
	mail_text = argv[1]
	msg = MIMEMultipart()
	msg['From'] = user
	msg['To'] = rcpt_to
	msg['Subject'] = subject
	body = MIMEText(mail_text, 'plain')
	msg.attach(body)

	with open(filename, 'r') as f:
		attachement = MIMEApplication(f.read(), Name=basename(filename))
		attachement['Content-Disposition'] = 'attachement; filename="{}"'.format(basename(filename))

	# Hänge Anhang an Nachricht
	msg.attach(attachement)

	send_mail(msg,user,pwd,smtp_server,smtp_port,mail_from,rcpt_to)

if __name__ == "__main__":
	main(sys.argv)
