# ConnectionVisualizer
This tool will take a PCAP file exported to csv and display a chord diagram in HTML along with bar graphs showing top connections. 
To export a PCAP file to CSV: File -> Export Packet Dissections -> as CSV... 
Usage: Place all files in your website directory. Run the python script using python 3
  Linux – python3 connection.py 
  Windows – python.exe connection.py
When it asks for input, give it the path to the PCAP in CSV file. The python script creates a readme.json file that the graph.html file reads to get its data. It also creates multiple TSV files, which is the data for the other html files.
