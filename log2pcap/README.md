# log2pcap
a simple python script to convert a packet dump(with ethernet header) to pcap file format


input:
  input.txt
  binary dump of a packet(with ethernet header)
  format: print 2 ascii code for each byte and seperate each bytes with a space
  example: 08 60 64 e9 0c .......

output:
  output.pcap
