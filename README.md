# ConnectionVisualizer
Christian Motta - cjm1594@rit.edu
Hans Johnson - hcj4880@rit.edu
Jon Massari - jsm5786@rit.edu

Prerequisites:
	Python 3 is installed
	A web service is installed. I.e. apache/IIS/etc.
	Tshark is installed

This tool will take a PCAP, generating a csv which is parsed to display a chord diagram in HTML along with bar graphs showing top connections. 

CSV's are also labeled by system run time and placed in a history directory. Future plans are to be able to access historical data from the web interface.

Usage: Place all files in your website directory. Run the python script using python 3
  Linux – python3 connections.py 
  Windows – python.exe connections.py
When it asks for input, give it the path to the PCAP. The python script creates a readme.json file that the graph.html file reads to get its data. It also creates multiple TSV files, which is the data for the other html files.

Note: Tool utilizes Bar Chart IIIC (https://bl.ocks.org/mbostock/7441121) and Chord Diagram (https://bl.ocks.org/mbostock/1046712) by Mike Bostock. The code for Bar Chart IIIC was slightly modified to remove digit formatting and to change the TSV headers being read to the ones generated by our code.
