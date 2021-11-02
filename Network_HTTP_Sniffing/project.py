from pcapy import *
from struct import *

# http number
no = 0

# return data list to ints
def IP_addr(a) :
	b = []
	for i in range(len(a)):
		b.append("%.2d" % a[i])
	return ".".join(b)

# 6.print captured http header
def cap_print(header, packet):

	# if not http, func close
	if packet.find(b'HTTP') == -1:
		return None

	global no
	no += 1

	# -----Ethernet------------------------------------------
	start_len = 0

	eth_len = 14
	# -----IP------------------------------------------------
	start_len += eth_len

	ip_len = 20
	ip_header = packet[start_len:start_len + ip_len]
	ip = unpack('!BBHHBBBBH8B', ip_header)
	ip_len = (ip[0] & 0xF)*4
	# -----TCP-----------------------------------------------
	start_len += ip_len

	tcp_len = 20
	tcp_header = packet[start_len:start_len + tcp_len]
	tcp = unpack('!HHLLBBHHH', tcp_header)
	tcp_len = (tcp[4]>>4)*4
	# -----HTTP----------------------------------------------
	start_len += tcp_len

	#get http header 
	http = packet[start_len:]
	rn_i = http.find(b'\r\n\r\n')
	http = http[:rn_i]
	# -------------------------------------------------------
	# select request/response
	state = ''
	if http.find(b'GET') != -1:
		state = 'Request'
		http = http[http.find(b'GET'):]
	elif http.find(b'POST') != -1:
		state = 'Request'
		http = http[http.find(b'POST'):]
	else:
		state = 'Response'
		http = http[http.find(b'HTTP'):]

	# print: ip protocol, sip,spt,dip,dpt 
	print('%s %s:%s %s:%s HTTP %s' % (no, IP_addr(ip[9:13]), tcp[0], IP_addr(ip[13:17]), tcp[1], state) )

	# print: http
	http = str(http, 'utf-8')
	print(http)
	
	print('\r\n\r\n')

#0.device search
devices = findalldevs()

#1.print devices
print('devices: ')
for idx in range(len(devices)):
	print("%d : %s" % (idx, devices[idx]))

#2.select device
dv_idx = input('select device: ')

#3.device's http network open
cap = open_live(devices[int(dv_idx)], 15000, 1, 20)
cap.setfilter('tcp port 80') #HTTP filter

#4.exception : no device network
if cap is None:
	print('No Open Live!')
	exit(0)

print('\r\n')

#5.in captured http...
cap.loop(-1, cap_print)

