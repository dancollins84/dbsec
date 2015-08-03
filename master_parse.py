#! usr/bin/env python

# Import Statements
import sys
from lxml import etree

# Invoke script by passing nmap .xml file and Nessus .nessus file.  Ex., 'python dbsec_parser.py scan.xml scan.nessus'
def main (nmap_filepath, nessus_filepath):
	nmap_tree = etree.parse(nmap_filepath)
	nessus_tree = etree.parse(nessus_filepath)
	scan_data_tag = etree.Element("scan_data") # root xml tag

	# The following code parses the nmap data and creates the discovery xml for the discovery table
	discovery_tag = etree.SubElement(scan_data_tag, "discovery")
	disc_id = 0
	
	for host in nmap_tree.xpath("host"):
		
		for address in host.xpath("address"):
			if address.attrib.get("addrtype") == "ipv4":
				addr_value = address.attrib.get("addr")

		for status in host.xpath("status"):
			if status.attrib.get("state") == "up":
				for ports in host.xpath("ports"):
					for port in ports.xpath("port"):
						for state in port.xpath("state"):
							if state.attrib.get("state") != "filtered":
								port_value = port.attrib.get("portid")
								protocol_value = port.attrib.get("protocol")
								state_value = state.attrib.get("state")

								for service in port.xpath("service"):
									service_name = service.attrib.get("name")

								disc_host_tag = etree.SubElement(discovery_tag, "disc_host")
								disc_id_tag = etree.SubElement(disc_host_tag, "disc_id")
								disc_id_tag.text = str(disc_id)
								disc_id += 1
								disc_host_ip_tag = etree.SubElement(disc_host_tag, "host_ip")
								disc_host_ip_tag.text = addr_value
								port_num_tag = etree.SubElement(disc_host_tag, "port_num")
								port_num_tag.text = port_value
								protocol_tag = etree.SubElement(disc_host_tag, "protocol")
								protocol_tag.text = protocol_value
								state_tag = etree.SubElement(disc_host_tag, "port_state")
								state_tag.text = state_value
								service_tag = etree.SubElement(disc_host_tag, "service")
								service_tag.text = service_name

	# The following code parses the nessus file and creates the hosts xml for the hosts table
	hosts_tag = etree.SubElement(scan_data_tag, "hosts")
	host_ip_value = ''
	host_name_value = ''
	host_os_value = ''
	host_mac_value = ''

	for Report in nessus_tree.xpath("Report"):
	
		for ReportHost in Report.xpath("ReportHost"):
		
			for HostProperties in ReportHost.xpath("HostProperties"):
			
				for tag in HostProperties.xpath("tag"):
					if tag.attrib.get("name") == "host-ip":
						host_ip_value = tag.text
					if tag.attrib.get("name") == "host-fqdn":
						host_name_value = tag.text
					if tag.attrib.get("name") == "operating-system":
						host_os_value = tag.text
					if tag.attrib.get("name") == "mac-address":
						host_mac_value = tag.text
			
				host_tag = etree.SubElement(hosts_tag, "host")				
				host_ip_tag = etree.SubElement(host_tag, "host_ip")
				host_ip_tag.text = host_ip_value
				host_name_tag = etree.SubElement(host_tag, "host_name")
				host_name_tag.text = host_name_value
				host_os_tag = etree.SubElement(host_tag, "host_os")
				host_os_tag.text = host_os_value
				host_mac_tag = etree.SubElement(host_tag, "mac_address")
				host_mac_tag.text = host_mac_value

				host_ip_value = ''
				host_name_value = ''
				host_os_value = ''
				host_mac_value = ''

	# The following code parses the nessus file and creates the software xml for the software table
	software_tag = etree.SubElement(scan_data_tag, "software")
	software_id = 0

	for Report in nessus_tree.xpath("Report"):
	
		for ReportHost in Report.xpath("ReportHost"):
		
			for HostProperties in ReportHost.xpath("HostProperties"):
				for tag in HostProperties.xpath("tag"):
					if tag.attrib.get("name") == "host-ip":
						host_ip_tag_value = tag.text

				for tag in HostProperties.xpath("tag"):
					if tag.attrib.get("name").startswith("cpe"):
						tag_value = tag.text
						cpe_newline_split = tag_value.split("\n")
						for elem in cpe_newline_split:
							cpe_colon_split = elem.split(":")
							cpe_colon_split[0] = host_ip_tag_value
							for i in range (1, 6):
								if i > len(cpe_colon_split):
									cpe_colon_split.append("")
							cpe_tag = etree.SubElement(software_tag, "cpe")
							software_id_tag = etree.SubElement(cpe_tag, "software_id")
							software_id_tag.text = str(software_id)
							software_id += 1
							host_ip_tag = etree.SubElement(cpe_tag, "host_ip")
							host_ip_tag.text = cpe_colon_split[0]
							part_tag = etree.SubElement(cpe_tag, "part")
							part_tag.text = cpe_colon_split[1]
							vendor_tag = etree.SubElement(cpe_tag, "vendor")
							vendor_tag.text = cpe_colon_split[2]
							product_tag = etree.SubElement(cpe_tag, "product")
							product_tag.text = cpe_colon_split[3]
							version_tag = etree.SubElement(cpe_tag, "version")
							version_tag.text = cpe_colon_split[4]

	# The following code parses the nessus file and creates the vulnerabilities xml for the vulnerabilities table
	vulns_tag = etree.SubElement(scan_data_tag, "vulnerabilities")
	vuln_id = 0

	for Report in nessus_tree.xpath("Report"):
	
		for ReportHost in Report.xpath("ReportHost"):

			severity_tag_value = ''
			plugin_tag_value = ''
			plugin_family_tag_value = ''
			vunl_name_tag_value = ''
			desc_tag_value = ''
			plugin_date_tag_value = ''
			cvss_base_tag_value = ''
			cvss_temp_tag_value = ''
			exploitable_tag_value = ''
		
			for HostProperties in ReportHost.xpath("HostProperties"):
				
				for tag in HostProperties.xpath("tag"):
					if tag.attrib.get("name") == "host-ip":
						vuln_host_ip_tag_value = tag.text

			for ReportItem in ReportHost.xpath("ReportItem"):
				severity_tag_value = ReportItem.attrib.get("severity")
				plugin_tag_value = ReportItem.attrib.get("pluginID")
				plugin_family_tag_value = ReportItem.attrib.get("pluginFamily")
				vuln_name_tag_value = ReportItem.attrib.get("pluginName")

				for description in ReportItem.xpath("description"):
					desc_tag_value = description.text

				for plugin_publication_date in ReportItem.xpath("plugin_publication_date"):
					plugin_date_tag_value = plugin_publication_date.text

				for cvss_base in ReportItem.xpath("cvss_base_score"):
					cvss_base_tag_value = cvss_base.text

				for cvss_temp in ReportItem.xpath("cvss_temporal_score"):
					cvss_temp_tag_value = cvss_temp.text

				for exploitable in ReportItem.xpath("exploit_available"):
					exploitable_tag_value = exploitable.text

				vuln_tag = etree.SubElement(vulns_tag, "vulnerability")				
				vuln_id_tag = etree.SubElement(vuln_tag, "vuln_id")
				vuln_id_tag.text = str(vuln_id)
				vuln_id += 1
				vuln_host_ip_tag = etree.SubElement(vuln_tag, "host_ip")
				vuln_host_ip_tag.text = vuln_host_ip_tag_value
				severity_tag = etree.SubElement(vuln_tag, "severity")
				severity_tag.text = severity_tag_value
				vuln_name_tag = etree.SubElement(vuln_tag, "vuln_name")
				vuln_name_tag.text = vuln_name_tag_value
				desc_tag = etree.SubElement(vuln_tag, "desc")
				desc_tag.text = desc_tag_value
				plugin_tag = etree.SubElement(vuln_tag, "plugin")
				plugin_tag.text = plugin_tag_value
				plugin_family_tag = etree.SubElement(vuln_tag, "plugin_family")
				plugin_family_tag.text = plugin_family_tag_value
				cvss_base_tag = etree.SubElement(vuln_tag, "cvss_base")
				cvss_base_tag.text = cvss_base_tag_value
				cvss_temp_tag = etree.SubElement(vuln_tag, "cvss_temp")
				cvss_temp_tag.text = cvss_temp_tag_value 
				exploitable_tag = etree.SubElement(vuln_tag, "exploitable")
				exploitable_tag.text = exploitable_tag_value

	# The following code parses the nessus file and creates the cve xml for the cve table
	cves_tag = etree.SubElement(scan_data_tag, "CVEs")
	cve_id = 0

	for Report in nessus_tree.xpath("Report"):
	
		for ReportHost in Report.xpath("ReportHost"):

			for ReportItem in ReportHost.xpath("ReportItem"):
				cve_plugin_tag_value = ReportItem.attrib.get("pluginID")
				for cve in ReportItem.xpath("cve"):
					cve_tag = etree.SubElement(cves_tag, "cve")
					cve_id_tag = etree.SubElement(cve_tag, "cve_id")
					cve_id_tag.text = str(cve_id)						
					cve_id += 1
					cve_plugin_tag = etree.SubElement(cve_tag, "plugin")
					cve_plugin_tag.text = cve_plugin_tag_value
					cve_tag = etree.SubElement(cve_tag, "cve_num")
					cve_tag.text = cve.text

	print(etree.tostring(scan_data_tag, pretty_print=True))	#print to console						

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
	
