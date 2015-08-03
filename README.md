# dbsec
A set of scripts to parse nmap / Nessus data and import XML data into a MySQL database.

## Required
-Python 2.7
-MySQL 5.5
-mysqlclient 1.3.6
-nmap
-Nessus
### (Optional)
-MySQL Workbench
-PHPmyadmin

## Files
1. README.md
2. dbsec_database.sql
3. batch_import.sql
4. master_parse.py

## Description
The dbsec project is designed to create a foundation to better analyze vulnerability scan data.  The majority of vulnerability scanners on the market produce xml and csv data exports for analysts to crawl through, which can be tedious.  While some may rely on command line parsing tools, and others might depend more heavily upon a collection of specialized scripts, the dbsec project aims to pull the most relevant information from a scan report and load it into a database.  Once in a database, the user can utilize SQL to analyze the information more effectively.  Additionally, information in a database can easily be linked to a web framework, such as Django, for reporting purposes.

## Instructions
1. Download the required software.  At a minimum, you will need to install Python 2.7 or greater and MySQL 5.5.  Keep in mind that to run locally, you will need both the MySQL client and MySQL server running.  Additionally, tools such as MySQL Workbench or PHPmyadmin can be handy to manage your databases.
2. Generate nmap / Nessus xml data.  Both products are free (Nessus for home users).
3. Execute 'master_parse.py' with the nmap and Nessus xml files as command line arguments.  By default, output is displayed in the terminal.
    ex. 'python master_parse.py nmap.xml data.nessus > output.xml'
4. Using either command line, or one of the GUI options listed above, connect to the database server.  Create the database using the 'dbsec_database.sql' file.
5. Again, from command line or GUI, access the database server.  Run the 'batch_import.sql' file, but take note of the lines that need to be replaced.  Most text editors support a 'replace-all' function, which is typically ctrl+h.
