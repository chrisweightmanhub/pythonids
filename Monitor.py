# Monitor unit V1.0
# Christopher Weightman 2020. All rights reserved.

import socket, struct, datetime, time
from Packet import *

class Monitor:
    
    def endConnection(self):
        s.close() # close socket connection
    
    def saveLog(self, logFileLocation):
    
        global logList, timer
        timer = time.time() # set timer
        logList.append('-----------------') # padding text for end of log entry
    
        if (len(logList) > 3):
            with open(logFileLocation, 'a') as logFile: # load log file at specified location
                for line in logList: 
                    logFile.write("%s\n" % line) # write log entry to log file
        
        currentDateTime = datetime.datetime.now()
        logList = [currentDateTime.strftime('%c'), '-----------------']
            
    def printLog(self):
        print(logList) # prints entire log entry for that session

    def unpackICMPPacket(self, IPPayload):
        messageType, code, checksum = struct.unpack('! B B H', IPPayload[:4]) # unpack ICMP packet into header elements and data
        return messageType, code, checksum, IPPayload[4:]

    def unpackTCPPacket(self, TCPPayload):
        sourcePort, destinationPort, sequenceNum, acknowledgementNum, offsetReservedFlags = struct.unpack('! H H L L H', TCPPayload[:14]) # unpack TCP packet into header elements and data
        offset = (offsetReservedFlags >> 12) * 4 # calculate poisition of data in relation to TCP header
        flagURG = (offsetReservedFlags & 32) >> 5 # bitshift flags section of packet header to get URG flag
        flagACK = (offsetReservedFlags & 16) >> 4 # bitshift flags section of packet header to get ACK flag
        flagPSH = (offsetReservedFlags & 8) >> 3 # bitshift flags section of packet header to get PSH flag
        flagRST = (offsetReservedFlags & 4) >> 2 # bitshift flags section of packet header to get RST flag
        flagSYN = (offsetReservedFlags & 2) >> 1 # bitshift flags section of packet header to get SYN flag
        flagFIN = (offsetReservedFlags & 1) # bitshift flags section of packet header to get FIN flag
        return sourcePort, destinationPort, sequenceNum, acknowledgementNum, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, TCPPayload[offset:]

    def unpackUDPPacket(self, IPPayload):
        sourcePort, destinationPort, size = struct.unpack('! H H 2x H', IPPayload[:8]) # unpack UDP packet into header elements and data
        return sourcePort, destinationPort, size, IPPayload[8:]
 
    def makeIPV4Readable(self, addr):
        return '.'.join(map(str, addr)) # convert address into readable format
    
    def unpackIPV4Frame(self, data):
        versionHeaderLength = data[0] # version header length is set as first byte from data
        versionNumber = versionHeaderLength >> 4 # version header length is bitshifted to find version number
        headerLength = (versionHeaderLength & 15) * 4 # header length is calculated
        ttl, protocol, sourceAddress, targetAddress = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # unpack IPV4 packet into header elements and data
        return versionNumber, headerLength, ttl, protocol, self.makeIPV4Readable(sourceAddress), self.makeIPV4Readable(targetAddress), data[headerLength:]

    def unpackEthernetFrame(self, data):
        destinationMAC, sourceMAC, protocol = struct.unpack('! 6s 6s H', data[:14]) # unpack TCP packet into header elements and data
        return self.makeMACReadable(destinationMAC), self.makeMACReadable(sourceMAC), socket.htons(protocol), data[14:]

    def makeMACReadable(self, bytesMACAddress):
        stringOfBytes = map('{:02x}'.format, bytesMACAddress) # use map function to convert MAC address to readable format
        return ':'.join(stringOfBytes).upper() # join address elements into full address
    
    def startMonitoringConnection(self):        
        
        global s
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # create new socket connection with correct Linux protocols for the collection of raw data packets

    def main(self):
            
        packet = None
        rawPacketData, address = s.recvfrom(65536) # pick up packet on socket connection (max buffer size 65536)
        destinationMAC, sourceMAC, ethernetProtocol, ethernetPayload = self.unpackEthernetFrame(rawPacketData)
        
        if ethernetProtocol == 8: # if packet is an IPV4 packet
            versionNumber, headerLength, ttl, protocol, sourceIP, destinationIP, IPPayload = self.unpackIPV4Frame(ethernetPayload)
            
            if protocol == 0: # if packet is an ICMP packet
                messageType, code, checksum, ICMPPayload = self.unpackICMPPacket(IPPayload) 
                newLogLine = ('ICMP Packet ' + str(destinationIP) + ' - Message type: ' + str(messageType) + ' Code: ' + str(code)) # line for log entry
                logList.append(newLogLine) # add line to log entry
                packet = ICMPPacket(destinationIP, messageType, code, checksum, ICMPPayload, time.time()) # create new ICMP packet object with data collected from packet
                    
            elif protocol == 6: # if packet is a TCP packet
                sourcePort, destinationPort, sequenceNum, acknowledgementNum, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, TCPPayload = self.unpackTCPPacket(IPPayload)
                newLogLine = ('TCP Packet ' + str(destinationIP) + ' - Source port: ' + str(sourcePort) + ' Destination port: ' + str(destinationPort) + ' Sequence number: ' + str(sequenceNum) + ' Acknowledgement number: ' + str(acknowledgementNum) + ' Flags: ' + str(flagURG) + str(flagACK) + str(flagPSH) + str(flagRST) + str(flagSYN) + str(flagFIN)) # line for log entry
                logList.append(newLogLine) # add line to log entry
                packet = TCPPacket(destinationIP, sourcePort, destinationPort, sequenceNum, acknowledgementNum, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, TCPPayload, time.time()) # create new TCP packet object with data collected from packet      
            
            elif protocol == 17: # if packet is a UDP packet
                sourcePort, destinationPort, size, UDPPayload = self.unpackUDPPacket(IPPayload)
                newLogLine = ('UDP Packet ' + str(destinationIP) + ' - Source port: ' + str(sourcePort) + ' Destination port: ' + str(destinationPort) + ' Size:  ' + str(size)) # line for log entry
                logList.append(newLogLine) # add line to log entry
                packet = UDPPacket(destinationIP, sourcePort, destinationPort, size, UDPPayload, time.time()) # create new UDP packet object with data collected from packet
        
        if timer + 15 < time.time(): # check if 15 seconds have passed since last log save
            self.saveLog('DataLogFile.txt')
                
        return packet
    
    def __init__(self):
                
        global logList, timer
        currentDateTime = datetime.datetime.now() # calculate current system time
        timer = time.time()
        logDateTime = 'Network logs for ' + (currentDateTime.strftime('%c')) # start log entry in human readable format
        logList = [logDateTime, '-----------------']