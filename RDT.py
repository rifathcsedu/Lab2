import Network
import argparse
from time import sleep
import time
import hashlib
import logging


class Packet:
	## the number of bytes used to store packet length
	seq_num_S_length = 10
	length_S_length = 10
	## length of md5 checksum in hex
	checksum_length = 32 
        
	def __init__(self, seq_num, msg_S):
		self.seq_num = seq_num
		self.msg_S = msg_S
	    
	@classmethod
	def from_byte_S(self, byte_S):
	    if Packet.corrupt(byte_S):
	        raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
	    #extract the fields
	    seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
	    msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
	    return self(seq_num, msg_S)
	    
	    
	def get_byte_S(self):
	    #convert sequence number of a byte field of seq_num_S_length bytes
	    seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
	    #convert length to a byte field of length_S_length bytes
	    length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
	    #compute the checksum
	    checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
	    checksum_S = checksum.hexdigest()
	    #compile into a string
	    return length_S + seq_num_S + checksum_S + self.msg_S


	@staticmethod
	def corrupt(byte_S):
	    #extract the fields
	    length_S = byte_S[0:Packet.length_S_length]
	    seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
	    checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
	    msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
	    
	    #compute the checksum locally
	    checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
	    computed_checksum_S = checksum.hexdigest()
	    #and check if the same
	    return checksum_S != computed_checksum_S
        

class RDT:


	rcv_msg = None
	logging.basicConfig(filename="RDT.log", level=logging.INFO, filemode="w")

	def __init__(self, role_S, server_S, port):
		## latest sequence number used in a packet
		self.seq_num = 1
		self.snd = 0
		self.rcv = 0
		## buffer of bytes read from network
		self.byte_buffer = ''

		self.RDTlogger = logging.getLogger("RDTLog")
		self.RDTlogger.info("\n RDT initiated \n ")
		self.network = Network.NetworkLayer(role_S, server_S, port)
		self.packetMessage = None
		self.pkCounter_seq0 = 1
		self.pkCounter_seq1 = 1

	def disconnect(self):
	    self.network.disconnect()
	    
	def rdt_1_0_send(self, msg_S):
	    p = Packet(self.seq_num, msg_S)
	    self.seq_num += 1
	    self.network.udt_send(p.get_byte_S())
	    
	def rdt_1_0_receive(self):
	    ret_S = None
	    byte_S = self.network.udt_receive()
	    self.byte_buffer += byte_S
	    #keep extracting packets - if reordered, could get more than one
	    while True:
	        #check if we have received enough bytes
	        if(len(self.byte_buffer) < Packet.length_S_length):
	            return ret_S #not enough bytes to read packet length
	        #extract length of packet
	        length = int(self.byte_buffer[:Packet.length_S_length])
	        if len(self.byte_buffer) < length:
	            return ret_S #not enough bytes to read the whole packet
	        #create packet from buffer content and add to return string
	        p = Packet.from_byte_S(self.byte_buffer[0:length])

	        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S

	        #remove the packet bytes from the buffer
	        self.byte_buffer = self.byte_buffer[length:]
	        #if this was the last packet, will return on the next iteration



	def seq_select(self,counter):
	    sq =  (counter+1) % 2;
	    self.seq_num = sq

	def rdt_2_1_send(self, msg_S):
		self.packetMessage = None
		p = Packet(self.seq_num, msg_S)
		self.seq_select(self.seq_num)
		self.packetMessage = p
		self.network.udt_send(p.get_byte_S())
	    # TODO: if !corrupt & !isNAK then goto seq_num = 1


	def rdt_2_1_receive(self):
		ret_S = None
		NACK = '-10'
		ACK = '-11'
		byte_S = self.network.udt_receive()
		self.byte_buffer += byte_S

		while True:

			if(len(self.byte_buffer) < Packet.length_S_length):
				return ret_S
			length = int(self.byte_buffer[:Packet.length_S_length])
			if len(self.byte_buffer) < length:
				return ret_S
			try:

				p = Packet.from_byte_S(self.byte_buffer[0:length])
				self.byte_buffer = self.byte_buffer[length:]
				if(p.msg_S == '-10'): # NACK resend
					if (self.packetMessage != None):
						
						self.network.udt_send(self.packetMessage.get_byte_S())
					else:
						
						np = Packet(p.msg_S, NACK)
						self.network.udt_send(np.get_byte_S())
					return None

				elif ((p.msg_S == '-11')):  # ACK do nothing
					
					self.packetMessage = None
					return None

				else:
					if (p.seq_num == 0):
						self.pkCounter_seq1 = 1
						if (self.pkCounter_seq0 == 1):
							self.pkCounter_seq0 = self.pkCounter_seq0+1
							ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
							
							#seq_select(self.seq_num+1) # alternate between 0 and 1
						elif (self.pkCounter_seq0 >= 2):
							self.pkCounter_seq0 = self.pkCounter_seq0+1
							
						ACKage = Packet(p.seq_num, ACK)
						self.network.udt_send(ACKage.get_byte_S())
					elif (p.seq_num == 1):
						self.pkCounter_seq0 = 1
						if (self.pkCounter_seq1 == 1):
							self.pkCounter_seq1 = self.pkCounter_seq1+1
							ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
							
							#seq_select(self.seq_num+1) # alternate between 0 and 1
						elif (self.pkCounter_seq1 >= 2):
							self.pkCounter_seq1 = self.pkCounter_seq1+1
							
						ACKage = Packet(p.seq_num, ACK)
						self.network.udt_send(ACKage.get_byte_S())

			except RuntimeError:
				
				self.byte_buffer = self.byte_buffer[length:]
				np = Packet(self.seq_num, NACK)
				self.network.udt_send(np.get_byte_S())



	def rdt_3_0_send(self, msg_S):
		self.packetMessage = None
		self.snd = 1
		p = Packet(self.seq_num, msg_S)
		self.seq_select(self.seq_num)
		self.packetMessage = p
		self.network.udt_send(p.get_byte_S())
	    

	def rdt_3_0_receive(self):
		timeout = 0
		time_of_last_data = time.time()
		ret_S = None
		NACK = '-10'
		ACK = '-11'
		byte_S = self.network.udt_receive()
		self.byte_buffer += byte_S
		while(True):
			if(len(self.byte_buffer) < Packet.length_S_length):
				return ret_S
			length = int(self.byte_buffer[:Packet.length_S_length])
			if len(self.byte_buffer) < length:
				return ret_S
			try:

				p = Packet.from_byte_S(self.byte_buffer[0:length])
				self.byte_buffer = self.byte_buffer[length:]
				if (self.snd == 1):
					print(p.msg_S )
					if ((p.msg_S == '-10') | (p.msg_S == '-11')):
						if(p.msg_S == '-10'): # NACK resend
							if (self.packetMessage != None):
								self.snd == 1
								print("NACK recieved sent back the original message")
								self.network.udt_send(self.packetMessage.get_byte_S())
							else:
								self.snd == 1
								print("NACK recieved sent back NACK again")
								np = Packet(p.msg_S, NACK)
								self.network.udt_send(np.get_byte_S())
							return None

						elif ((p.msg_S == '-11')):  # ACK do nothing
							print("ACK recieved and SeqNumber changes to package copy clean",self.seq_num )
							self.packetMessage = None
							self.snd  = 0
							return None

					else:
						if time_of_last_data + timeout < time.time():
							break
						else:
							continue
					time_of_last_data = time.time()

				else:
					if (p.seq_num == 0 & p.seq_num == self.seq_num):
						self.pkCounter_seq1 = 1
						if (self.pkCounter_seq0 == 1):
							self.pkCounter_seq0 = self.pkCounter_seq0+1
							ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
							print("RCV MSG  Seq = 0  r = 1 ACK sent")
							#seq_select(self.seq_num+1) # alternate between 0 and 1
						elif (self.pkCounter_seq0 >= 2):
							self.pkCounter_seq0 = self.pkCounter_seq0+1
							print("RCV MSG Seq = 0  r > 2 ACK sent")

						ACKage = Packet(p.seq_num, ACK)
						self.snd  = 1
						self.network.udt_send(ACKage.get_byte_S())
					elif (p.seq_num == 1 &  p.seq_num == self.seq_num):
						self.pkCounter_seq0 = 1
						if (self.pkCounter_seq1 == 1):
							self.pkCounter_seq1 = self.pkCounter_seq1+1
							ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
							print("RCV MSG Seq = 1  r = 1 ACK sent")
							#seq_select(self.seq_num+1) # alternate between 0 and 1
						elif (self.pkCounter_seq1 >= 2):
							self.pkCounter_seq1 = self.pkCounter_seq1+1
							print("RCV MSGSeq = 1  r > 2 ACK sent")
						ACKage = Packet(p.seq_num, ACK)
						self.snd  = 1
						self.network.udt_send(ACKage.get_byte_S())
					else: # we had loss packages and need to resend it 
						if (self.packetMessage != None):
							print("NACK recieved sent back the original message")
							self.network.udt_send(self.packetMessage.get_byte_S())
						else:
							print("NACK recieved sent back NACK again")
							np = Packet(p.msg_S, NACK)
							self.network.udt_send(np.get_byte_S())


			except RuntimeError:
				print("NACK sent package currp on seq on ", self.seq_num)
				self.byte_buffer = self.byte_buffer[length:]
				np = Packet(self.seq_num, NACK)
				self.snd  = 1
				self.network.udt_send(np.get_byte_S())

			
		self.network.udt_send(self.packetMessage.get_byte_S())
		return None





	    

if __name__ == '__main__':


	parser =  argparse.ArgumentParser(description='RDT implementation.')
	parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
	parser.add_argument('server', help='Server.')
	parser.add_argument('port', help='Port.', type=int)
	args = parser.parse_args()
	rdt = RDT(args.role, args.server, args.port)
	if args.role == 'client':
	    rdt.rdt_1_0_send('MSG_FROM_CLIENT')
	    sleep(2)
	    print(rdt.rdt_1_0_receive())
	    rdt.disconnect()
	    
	    
	else:
	    sleep(1)
	    print(rdt.rdt_1_0_receive())
	    rdt.rdt_1_0_send('MSG_FROM_SERVER')
	    rdt.disconnect()
	    


	    
	    