# Intrusion Detection System unit V1.0
# Christopher Weightman 2020. All rights reserved.

from Monitor import *
from Packet import *
import time, sys, pickle # in-built Python libraries

class IntrusionDetectionSystem:

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
    
    def loadUserRules(self): # load user-defined rules from rules data file
        
        global userRules
        rulesFile = open('rules.data', 'rb')
        userRules = pickle.load(rulesFile) # load all user rules into userRules list
        rulesFile.close()
        
    def checkForbiddenedPorts(self, currentPacket): # check if packet was sent to a fobidden port
        
        forbiddenedPorts = userRules[1] # get list of forbidden ports
        
        if forbiddenedPorts: # if any ports are forbidden
            for i3 in forbiddenedPorts:
                if (i3 != []):
                    if (type(currentPacket) == TCPPacket) or (type(currentPacket) == UDPPacket): # check that packet is TCP or UDP
                        if currentPacket.getDestinationPort() == i3: # if packet's destination port matches a forbidden port
                            lowPriorityAlerts.append('Address ' + str(currentPacket.getAddress()) + ' Tried to visit port ' + str(i3) + ', which is forbidden!') # generate forbidden port alert

    def forbiddenSpecificServices(self, currentPacket): # check if a packet violates a forbidden services rule
        
        forbiddenIPsSpecificServices = userRules[3] # get list of forbidden services
        
        for i3 in forbiddenIPsSpecificServices: # if any services are forbidden
            if (i3 != []):
                if i3 == currentPacket.getAddress(): # if packet is from any IP that forms part of a forbidden services rule
                    for count in range(1, len(i3)):
                        if currentPacket.getDestinationPort == i3[count]: # if packet is destined to interact with a forbidden service for that IP
                            lowPriorityAlerts.append('Address ' + str(currentPacket.getAddress()) + ' is not allowed to access services on port ' + str(i3[count])) # Generate forbidden service alert
        
    def clearPacketBuffer(self): # clear old entries from general packet buffer
        
        for i3 in packetBuffer: # if buffer is not empty
            if (i3 != []):
                if  (type(i3) == TCPPacket) or (type(i3) == UDPPacket) or (type(i3) == ICMPPacket): # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        packetBuffer.remove(i3)  # remove packet from buffer
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old
                            i3.remove(i4) # remove packet from buffer

    def addToPacketBuffer(self, currentPacket): # add any packet to buffer of recieved packets
        
        addressInBuffer = False
            
        for i3 in packetBuffer:
            if (i3 != []):
                if (isinstance(i3, TCPPacket)) or (isinstance(i3, UDPPacket)) or (isinstance(i3, ICMPPacket)):
                    if (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a packet
                        packetBuffer[packetBuffer.index(i3)] = [packetBuffer[packetBuffer.index(i3)],currentPacket]
                        addressInBuffer = True
                elif (isinstance(i3, list)):
                    if(currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of packets from one source address
                        i3.append(currentPacket) # adds to packet buffer in correct list location for relevant source address
                        addressInBuffer = True # do not add to packet buffer again as new entry
                
        if addressInBuffer == False: # if packets with the source address of the packet are not already present in buffer
            packetBuffer.append(currentPacket)

    def checkBandwidthDDoSAttack(self): # check for DDoS attack against host
        
        bandwidthBytes = 0
        
        for i3 in packetBuffer:
            if (i3 != []):
                if (type(i3) == TCPPacket) or (type(i3) == UDPPacket) or (type(i3) == ICMPPacket): # detect packet type, calculate size of packet and add to total count
                    if i3.getTime() +1 < time.time():        
                        if type(i3) == TCPPacket:
                            bandwidthBytes = bandwidthBytes + (sys.getsizeof(i3.getPayload()) + 20)       
                        if type(i3) == UDPPacket:
                            bandwidthBytes = bandwidthBytes + (sys.getsizeof(i3.getPayload()) + 8)            
                        if type(i3) == ICMPPacket:
                            bandwidthBytes = bandwidthBytes + (sys.getsizeof(i3.getPayload()) + 8)
                elif (type(i3) != TCPPacket) and (type(i3) != UDPPacket) and (type(i3) != ICMPPacket): # If entry is a list of packets from one source address
                    for i4 in i3: # detect packet type, calculate size of packet and add to total count
                        if i4.getTime() +1 < time.time(): 
                            if type(i4) == TCPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 20)       
                            if type(i4) == UDPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 8)            
                            if type(i4) == ICMPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 8)
                        
            if bandwidthBytes > 150000000: # value = 1500 average packet length * 1000 connections * 100 packets/second per connection
                highPriorityAlerts.append('Possible DDoS attack detected') # generate DDoS alert
                    
    def checkBandwidthDoSAttack(self):
        
        bandwidthBytes = 0
        
        for i3 in packetBuffer:
            if (i3 != []):
                if isinstance(i3, list):
                    for i4 in i3: # for each list of packets in packet buffer: detect packet type, calculate size of packet and add to total count
                        if i4.getTime() +1 < time.time(): # if age of packet is less than a second
                            if type(i4) == TCPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 20)       
                            if type(i4) == UDPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 8)            
                            if type(i4) == ICMPPacket:
                                bandwidthBytes = bandwidthBytes + (sys.getsizeof(i4.getPayload()) + 8)  
                
                    if bandwidthBytes > 15000000: # value = 1500 average packet length * 1000 packets/second
                        highPriorityAlerts.append('Possible DoS attack from ' + str(i3[0].getAddress())) # generate DoS alert
        
    def checkRequestsRate(self): # check that average request rate is not too high
        
        sourceAddressList = []
        averagePacketsPerUser = 0
        
        for i3 in packetBuffer:
            if (i3 != []):
                if (isinstance(i3, TCPPacket)) or (isinstance(i3, UDPPacket)) or (isinstance(i3, ICMPPacket)): # If entry in buffer is a packet
                    sourceAddressList.append(i3.getAddress()) # add unique source address to source address list
                elif isinstance(i3, list): # If entry in buffer is a list of packets from one source address 
                    for i4 in i3:
                        sourceAddressList.append(i4.getAddress()) # add unique source address to source address list
        
        sourceAddressListSet = set(sourceAddressList) # converting to set removes duplicate entries
        tempList = list(sourceAddressListSet) # shortened list for sending to GUI initialised
        
        if len(sourceAddressListSet) > 5:
            userInterfaceData[0] = tempList[:5] # small list of source addresses passed to GUI
        else:
            userInterfaceData[0] = tempList

        userInterfaceData[1] = len(sourceAddressListSet) # number of current active connections passed to GUI
                
        if len(sourceAddressListSet) != 0: # check for division by 0 error
            averagePacketsPerUser = len(sourceAddressList) / len(sourceAddressListSet) # average packet transfer rate per connection calculated
            
        userInterfaceData[2] = averagePacketsPerUser # transfer rate of packets per active connection passed to GUI
        
        if averagePacketsPerUser > 3000: # if a very high average packet transfer rate
            lowPriorityAlerts.append('Very high average request rate!') # generate high request rate alert

    def clearICMPBuffer(self): # clear old entries from ICMP buffer
        
        for i3 in ICMPBuffer:
            if (i3 != []):
                if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                    ICMPBuffer.remove(i3)  # remove packet from buffer

    def checkSmurfAttack(self): # checks for ICMP smurf attacks
        
        ICMPPacketsPerSecond = 0
        
        for i3 in ICMPBuffer: # count number of recent ICMP packets
            if (i3 != []):
                if i3.getTime() + 1 < time.time():
                    ICMPPacketsPerSecond = ICMPPacketsPerSecond + 1
                
        if ICMPPacketsPerSecond > 100: # if unreasonably high level of ICMP packets are recieved
            highPriorityAlerts.append('Possible ICMP smurf attack occuring') # generate ICMP smurf attack alert

    def checkEchoScan(self, currentPacket): # check for attempts to ping host device
        
        if currentPacket.getMessageType() == 8: # if echo request (ping) ICMP packet
            lowPriorityAlerts.append('ICMP echo request: Ping attempt from ' + str(currentPacket.getAddress())) # generate echo scan alert
        
    def clearUDPBuffer(self): # clear old entries from UDP packet buffer
                    
        for i3 in UDPBuffer: # if buffer is not empty
            if (i3 != []):
                if  type(i3) == UDPPacket: # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        UDPBuffer.remove(i3) # remove packet from buffer    
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old
                            i3.remove(i4)  # remove packet from buffer

    def checkUDPScan(self, currentPacket): # check for UDP scan
        
        addressInBuffer = False

        for i3 in UDPBuffer:
            if (i3 != []):        
                if (type(i3) == UDPPacket) and (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a UDP packet and source addresses match
                    UDPBuffer[UDPBuffer.index(i3)] = [UDPBuffer[UDPBuffer.index(i3)],currentPacket] # add packet to UDP buffer
                    addressInBuffer = True
                elif (type(i3) != UDPPacket) and (currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of UDP packets from one source address
                    i3.append(currentPacket) # add packet to UDP buffer at appropriate index
                    addressInBuffer = True
                
        if addressInBuffer == False: # if source address of packet not already present in UDP buffer
            UDPBuffer.append(currentPacket) # add UDP packet to UDP buffer
                    
        portValuesList = []
            
        for i3 in UDPBuffer:
            if (i3 != []):
                portValues = []    
                if (type(i3) == UDPPacket):
                    portValues.append(i3.getDestinationPort()) # add destination port of packet in buffer to port value list   
                else:
                    for i4 in i3:
                        portValues.append(i4.getDestinationPort())
                    
                portValuesList.append(portValues) # add destination port values to port value list
                                       
        for i3 in portValuesList:
            uniquePorts = set(i3) # remove duplicate entries from port list
            if len(uniquePorts) > 655: # check if any address has sent UDP packets to more than 655 different ports
                highPriorityAlerts.append('Possible UDP scan in progress by address ' + str(UDPBuffer[portValuesList.index(i3)][0].getAddress())) # generate UDP scan alert             
        
    def clearFINBuffer(self): # clear old entries from FIN packet buffer
                    
        for i3 in FINBuffer: # if buffer is not empty
            if (i3 != []):
                if  type(i3) == TCPPacket: # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        FINBuffer.remove(i3)  # remove packet from buffer           
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old
                            i3.remove(i4)  # remove packet from buffer

    def checkFINScan(self, currentPacket): # check for TCP FIN scan
        
        addressInBuffer = False

        for i3 in FINBuffer:
            if (i3 != []):
                
                if (type(i3) == TCPPacket) and (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a packet
                    FINBuffer[FINBuffer.index(i3)] = [FINBuffer[FINBuffer.index(i3)],currentPacket] # add FIN packet to FIN buffer
                    addressInBuffer = True
                elif (type(i3) != TCPPacket) and (currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of packets from one source address
                    i3.append(currentPacket) # add FIN packet to FIN buffer at appropriate index
                    addressInBuffer = True
                
        if addressInBuffer == False: # if source address of packet not already present in FIN buffer
            FINBuffer.append(currentPacket) # add FIN packet to FIN buffer
                    
        portValuesList = []
            
        for i3 in FINBuffer:
            if (i3 != []):
                portValues = []   
                if (type(i3) == TCPPacket):
                    portValues.append(i3.getDestinationPort()) # add destination port of packet in buffer to port value list   
                else:
                    for i4 in i3:
                        portValues.append(i4.getDestinationPort()) # add destination port values to port value list
                    
                portValuesList.append(portValues)
                                       
        for i3 in portValuesList:
            if (i3 != []):
                uniquePorts = set(i3) # remove duplicate entries from port list
                if len(uniquePorts) > 655: # check if any address has sent FIN packets to more than 655 different ports
                    highPriorityAlerts.append('Possible FIN scan in progress by address ' + str(FINBuffer[portValuesList.index(i3)][0].getAddress())) # generate FIN scan alert              
        
    def clearXMASBuffer(self): # clear old entries from XMAS packet buffer
                    
        for i3 in XMASBuffer: # if buffer is not empty
            if (i3 != []):
                if  type(i3) == TCPPacket: # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        XMASBuffer.remove(i3)  # remove packet from buffer   
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old
                            i3.remove(i4)  # remove packet from buffer

    def checkXMASScan(self, currentPacket): # check for TCP XMAS scan
        
        addressInBuffer = False
        
        for i3 in XMASBuffer: 
            if (i3 != []):
                if (type(i3) == TCPPacket) and (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a packet
                    XMASBuffer[XMASBuffer.index(i3)] = [XMASBuffer[XMASBuffer.index(i3)],currentPacket] # add XMAS packet to XMAS buffer
                    addressInBuffer = True
                elif (type(i3) != TCPPacket) and (currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of packets from one source address
                    i3.append(currentPacket) # add XMAS packet to XMAS buffer at appropriate index
                    addressInBuffer = True
                    
        if addressInBuffer == False: # if source address of packet not already present in XMAS buffer
            XMASBuffer.append(currentPacket) # add XMAS packet to XMAS buffer
                    
        portValuesList = []
            
        for i3 in XMASBuffer:
            if (i3 != []):
                portValues = []  
                if (type(i3) == TCPPacket):
                    portValues.append(i3.getDestinationPort()) # add destination port of packet in buffer to port value list
                else:
                    for i4 in i3:
                        portValues.append(i4.getDestinationPort()) # add destination port values to port value list
                    
                portValuesList.append(portValues)
                                       
        for i3 in portValuesList:
            if (i3 != []):
                uniquePorts = set(i3) # remove duplicate entries from port list
                if len(uniquePorts) > 655: # check if any address has sent XMAS packets to more than 655 different ports
                    highPriorityAlerts.append('Possible XMAS scan in progress by address ' + str(XMASBuffer[portValuesList.index(i3)][0].getAddress())) # generate XMAS scan alert               
        
    def clearNULLBuffer(self): # clear old entries from NULL packet buffer
                    
        for i3 in NULLBuffer: # if buffer is not empty
            if (i3 != []):
                if  type(i3) == TCPPacket: # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        NULLBuffer.remove(i3)  # remove packet from buffer       
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old 
                            i3.remove(i4)  # remove packet from buffer

    def checkNULLScan(self, currentPacket): # check for TCP NULL scan
        
        addressInBuffer = False
            
        for i3 in NULLBuffer:
            if (i3 != []):
                if (type(i3) == TCPPacket) and (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a packet
                    NULLBuffer[NULLBuffer.index(i3)] = [NULLBuffer[NULLBuffer.index(i3)],currentPacket] # add NULL packet to NULL buffer
                    addressInBuffer = True
                elif (type(i3) != TCPPacket) and (currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of packets from one source address
                    i3.append(currentPacket) # add NULL packet to NULL buffer at appropriate index
                    addressInBuffer = True
                
        if addressInBuffer == False: # if source address of packet not already present in NULL buffer
            NULLBuffer.append(currentPacket) # add NULL packet to NULL buffer
                    
        portValuesList = []
           
        for i3 in NULLBuffer:
            if (i3 != []):
                portValues = []  
                if (type(i3) == TCPPacket):
                    portValues.append(i3.getDestinationPort()) # add destination port of packet in buffer to port value list     
                else:
                    for i4 in i3:
                        portValues.append(i4.getDestinationPort()) # add destination port values to port value list
                    
                portValuesList.append(portValues) # remove duplicate entries from port list
                                       
        for i3 in portValuesList:
            if (i3 != []):
                uniquePorts = set(i3)
                if len(uniquePorts) > 655: # check if any address has sent NULL packets to more than 655 different ports
                    highPriorityAlerts.append('Possible NULL scan in progress by address ' + str(NULLBuffer[portValuesList.index(i3)][0].getAddress())) # generate NULL scan alert               
        
    def clearSYNBuffer(self): # clear old entries from SYN packet buffer
                    
        for i3 in SYNBuffer: # if buffer is not empty
            if (i3 != []):

                if  type(i3) == TCPPacket: # if entry in buffer is a packet
                    if i3.getTime() + 60 < time.time(): # check if packet is more than a minute old
                        SYNBuffer.remove(i3)  # remove packet from buffer   
                else: # if entry in buffer is a list of packets from one source address
                    for i4 in i3: # for every packet in this list
                        if i4.getTime() + 60 < time.time(): # check if packet is more than a minute old
                            i3.remove(i4)  # remove packet from buffer

    def checkSYNScan(self, currentPacket): # check for TCP SYN scan
        
        addressInBuffer = False
        
        for i3 in SYNBuffer:
            if (i3 != []):
                if (type(i3) == TCPPacket) and (currentPacket.getAddress() == i3.getAddress()): # if entry in buffer is a packet
                    SYNBuffer[SYNBuffer.index(i3)] = [SYNBuffer[SYNBuffer.index(i3)],currentPacket] # add SYN packet to SYN buffer
                    addressInBuffer = True
                elif (type(i3) != TCPPacket) and (currentPacket.getAddress() == i3[0].getAddress()): # if entry in buffer is a list of packets from one source address
                    i3.append(currentPacket) # add SYN packet to SYN buffer at appropriate index
                    addressInBuffer = True
                
        if addressInBuffer == False: # if source address of packet not already present in SYN buffer
            SYNBuffer.append(currentPacket) # add SYN packet to SYN buffer
                    
        portValuesList = []
            
        for i3 in SYNBuffer:
            if (i3 != []):
                portValues = []   
                if (type(i3) == TCPPacket):
                    portValues.append(i3.getDestinationPort()) # add destination port of packet in buffer to port value list      
                else:
                    for i4 in i3:
                        portValues.append(i4.getDestinationPort()) # add destination port values to port value list
                    
                portValuesList.append(portValues)
                                       
        for i3 in portValuesList:
            if (i3 != []):
                uniquePorts = set(i3) # remove duplicate entries from port list
                if len(uniquePorts) > 655: # check if any address has sent SYN packets to more than 655 different ports
                    highPriorityAlerts.append('Possible SYN scan in progress by address ' + str(SYNBuffer[portValuesList.index(i3)][0].getAddress())) # generate SYN scan alert               
       
    def checkSourceAddress(self, currentPacket): # checks source address of packet against a list of forbidden source addresses
        
        blacklistedIPs = userRules[0] # load list of forbidden source addresses
        
        for i3 in blacklistedIPs:
            if currentPacket.getAddress() == i3: # if packet source address matches any forbidden addresses
                lowPriorityAlerts.append('Blacklisted IP detected! ' + str(i3)) # generate forbidden IP detection alert
        
    def mainFunction(self, testingMode):
        
        global lowPriorityAlerts, highPriorityAlerts, logList, timer
        
        userInterfaceData[0] = [None] # reset variables which store data for passing to GUI
        userInterfaceData[4] = [None]
        packetPrintedString = None
        lowPriorityAlerts = [] # clear low priority alert buffer
        highPriorityAlerts = [] # clear high priority alert buffer
        self.loadUserRules()
        
        receivedPacket = None
        
        if testingMode[0] == True: # if program is running in testing mode
            receivedPacket = testingMode[1] # receive test packet
        else:
            receivedPacket = monitor.main() # get next detected packet from monitor
         
        if receivedPacket != None: # if a packet was detected
            
            # perform general checking functions with packet
            self.addToPacketBuffer(receivedPacket)    
            self.checkSourceAddress(receivedPacket)
            self.forbiddenSpecificServices(receivedPacket)
            self.checkForbiddenedPorts(receivedPacket)
            self.checkBandwidthDDoSAttack()
            self.checkBandwidthDoSAttack()
            self.checkRequestsRate()
                    
            if type(receivedPacket) == TCPPacket:
                
                if userRules[3] == 1: # if TCP packets are set to forbidden by the user
                    lowPriorityAlerts.append('TCP traffic detected!') # generate TCP traffic alert
                
                # check the flags within the TCP packet and call appropriate detection functions for these flags
                if (receivedPacket.getFlagURG() == 0) and (receivedPacket.getFlagACK() == 0) and (receivedPacket.getFlagPSH() == 0) and (receivedPacket.getFlagRST() == 0) and (receivedPacket.getFlagSYN() == 1) and (receivedPacket.getFlagFIN() == 0): # if SYN packet
                    self.checkSYNScan(receivedPacket)
                if (receivedPacket.getFlagURG() == 0) and (receivedPacket.getFlagACK() == 0) and (receivedPacket.getFlagPSH() == 0) and (receivedPacket.getFlagRST() == 0) and (receivedPacket.getFlagSYN() == 0) and (receivedPacket.getFlagFIN() == 0): # if NULL packet
                    self.checkNULLScan(receivedPacket)
                if (receivedPacket.getFlagURG() == 1) and (receivedPacket.getFlagACK() == 0) and (receivedPacket.getFlagPSH() == 1) and (receivedPacket.getFlagRST() == 0) and (receivedPacket.getFlagSYN() == 0) and (receivedPacket.getFlagFIN() == 1): # if XMAS packet 
                    self.checkXMASScan(receivedPacket)
                if (receivedPacket.getFlagURG() == 0) and (receivedPacket.getFlagACK() == 0) and (receivedPacket.getFlagPSH() == 0) and (receivedPacket.getFlagRST() == 0) and (receivedPacket.getFlagSYN() == 0) and (receivedPacket.getFlagFIN() == 1): # if FIN packet
                    self.checkFINScan(receivedPacket)
                    
            if type(receivedPacket) == UDPPacket:
                
                if userRules[3][1] == 1: # if UDP packets are set to forbidden by the user
                    lowPriorityAlerts.append('UDP traffic detected!') # generate ICMP traffic alert   
                
                # call UDP detection functions
                UDPBuffer.append(receivedPacket)
                self.checkUDPScan(receivedPacket)
                    
            if type(receivedPacket) == ICMPPacket:
                
                if userRules[3][2] == 1: # if ICMP packets are set to forbidden by the user
                    lowPriorityAlerts.append('ICMP traffic detected!') # generate ICMP traffic alert
                
                # call ICMP detection functions
                ICMPBuffer.append(receivedPacket)
                self.checkEchoScan(receivedPacket)
                self.checkSmurfAttack()
                                
        # clear all packet buffers
        self.clearPacketBuffer()
        self.clearUDPBuffer()
        self.clearICMPBuffer()
        self.clearSYNBuffer()
        self.clearNULLBuffer()
        self.clearXMASBuffer()
        self.clearFINBuffer()
            
        # populate variables with data for passing to user interface
        userInterfaceData[3] = highPriorityAlerts
        userInterfaceData[4] = lowPriorityAlerts

        if testingMode[0] == True: # print test packet details if program is running in testing mode
            print(receivedPacket.printPacket())
            
        for i in highPriorityAlerts:
            logList.append(i)
        for i in lowPriorityAlerts:
            logList.append(i)
            
        if timer + 10 < time.time(): # check if 15 seconds have passed since last log save
            self.saveLog('AlertLogFile.txt')
            
        return userInterfaceData # return data to user interface
        
    def __init__(self):
        
        global bandwidthBytes, packetBuffer, TCPBuffer, SYNBuffer, NULLBuffer, XMASBuffer, FINBuffer, UDPBuffer, ICMPBuffer, userInterfaceData, logList, timer
        
        # initialise global variables and lists
        userInterfaceData = [None, None, None, None, None, None]
        packetBuffer = []
        TCPBuffer = []

        SYNBuffer = []
        NULLBuffer = []
        XMASBuffer = []
        FINBuffer = []
        UDPBuffer = []
        ICMPBuffer = []
        
        # instantiate monitor object to capture network traffic
        global monitor
        monitor = Monitor()
        monitor.startMonitoringConnection()
        
        currentDateTime = datetime.datetime.now() # calculate current system time
        timer = time.time()
        logDateTime = 'Event logs for ' + (currentDateTime.strftime('%c')) # start log entry in human readable format
        logList = [logDateTime, '-----------------']