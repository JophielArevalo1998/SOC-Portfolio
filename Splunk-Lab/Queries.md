# Initial data check
index="mydifr-soc"

# Authentication analysis
index="mydifr-soc" sourcetype="WinEvent:Security" (EventCode=4625 OR EventCode=4624)
| stats count by Account_Name, src_ip, EventCode

# Successful logon from attacker
index="mydifr-soc" sourcetype="WinEvent:Security" src_ip=172.16.0.184 EventCode=4624
| table _time Account_Name Logon_Type src_ip

# Process execution (Sysmon)
index="mydifr-soc" sourcetype="WinEvent:Sysmon" EventCode=1
| table _time Image CommandLine User ParentImage

# Suspicious process filtering
index="mydifr-soc" sourcetype="WinEvent:Sysmon" EventCode=1
Image="C:\\Users\\Ryan.Adams\\Music\\python.exe"

# Network connections (C2)
index="mydifr-soc" sourcetype="WinEvent:Sysmon" EventCode=3
| table _time Image DestinationIp DestinationPort

# Filter on malicious IP
index="mydifr-soc" 157.245.46.190
| stats count by sourcetype, dest_port

# Persistence detection
index="mydifr-soc" CommandLine="*schtasks*"

# PowerShell activity
index="mydifr-soc" sourcetype="WinEvent:PowerShell"

# Defender logs
index="mydifr-soc" sourcetype="WinEvent:Defender"
``
