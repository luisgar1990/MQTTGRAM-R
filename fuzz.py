#!/usr/bin/env python3
#==============================================================================================
#    MQTTGRAM-H: An open-source and multi-version grammar-based fuzzer for the MQTT protocol.
#
#    This file is part of MQTTGRAM-H.
#
#    MQTTGRAM-H is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    MQTTGRAM-H is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with MQTTGRAM-H. If not, see <https://www.gnu.org/licenses/>.
#==============================================================================================



from sys import argv, exit
#from random import choice
#from numpy.random import choice
from random import choice, choices
import getopt
import os
import packets
import modes

#from scapy.contrib.mqtt import *
#from scapy.all import *

mqtt_pkts = [packets.mqtt_publish, packets.mqtt_subscribe, packets.mqtt_unsubscribe, packets.mqtt_ping, packets.mqtt_disconnect, packets.mqtt_random]
#mqtt_pkts = [packets.mqtt_publish, packets.mqtt_subscribe, packets.mqtt_unsubscribe, packets.mqtt_ping]
#weights = [0.25, 0.25, 0.25, 0.20, 0.05]

def main(argv):
    
    try:
        opts, args = getopt.getopt(argv, "r:gvh")

        for opt, arg in opts:
            if opt == "-r":
                random_mode=True
                attacker = arg

            if opt == "-g":
                #print("You are in grammar mode!")
                hybrid_mode = False
                attacker = None
                #exit(0) 
            
            if opt == "-v":
                #print("You are in grammar 5 mode!")
                hybrid_mode = False
                attacker = None
                #exit(0)
	    
            if opt == "-h":
                #print("You are in hybrid mode!")
                attacker = None
                hybrid_mode = True
                opt = choice(["-g", "-v"])
                #exit(0) 


    except getopt.GetoptError:
        packets.usage()

    #TCP HANDSHAKE
    #last_pkt = packets.tcp_handshake() #NEW
    ip_pkt, tcp_pkt, last_pkt = packets.tcp_handshake() #OLD

    #MQTT CONNECT
    #last_pkt = packets.mqtt_connect(last_pkt) #NEW
    ip_pkt, tcp_pkt, last_pkt = packets.mqtt_connect(ip_pkt, tcp_pkt, last_pkt, attacker, opt) #OLD

    if opt == "-r" or opt == "-g" or opt == "-v": #TODO: DONT NEED THIS IF...CAN REMOVE IT...

        while True:
            #NO WEIGHTS
            #random_mqtt_pkt = choice(mqtt_pkts)

            #WEIGHTS
            random_mqtt_pkt = choices(mqtt_pkts, weights=[25, 25, 25, 15, 5, 5])
            #print(random_mqtt_pkt)

            #last_pkt = random_mqtt_pkt(last_pkt) #NEW
            ip_pkt, tcp_pkt, last_pkt = random_mqtt_pkt[0](ip_pkt, tcp_pkt, last_pkt, opt) #OLD
            
            #if last_pkt is not None:
            if (last_pkt["TCP"].flags == "FA") or (last_pkt["TCP"].flags == "FPA") or (last_pkt["TCP"].flags == "R"): #TODO ADDED FLAGS ==R BECAUSE NORMALY RST OCCUR WHEN A FIN ACK PACKET IS SENT, SO IT NEEDS TO DISCONNECT. HOWEVER THIS IS NOT ALWAYS THE CASE.
                    #if (last_pkt["TCP"].flags != "R") and last_pkt.haslayer(MQTT):


                    #MQTT DISCONNECT 
                    #last_pkt = packets.mqtt_disconnect(last_pkt) #NEW
                 #   ip_pkt, tcp_pkt, last_pkt = packets.mqtt_disconnect(ip_pkt, tcp_pkt, last_pkt, opt) #OLD

                #TCP DISCONNECT
                #packets.tcp_disconnect(last_pkt) #NEW
                packets.tcp_disconnect(ip_pkt, tcp_pkt, last_pkt) #OLD

                #TCP HANDSHAKE
                #last_pkt = packets.tcp_handshake() #NEW
                ip_pkt, tcp_pkt, last_pkt = packets.tcp_handshake() #OLD

                if hybrid_mode == True: opt = choice(["-g", "-v"])

                #MQTT CONNECT
                #last_pkt = packets.mqtt_connect(last_pkt) #NEW
                ip_pkt, tcp_pkt, last_pkt = packets.mqtt_connect(ip_pkt, tcp_pkt, last_pkt, attacker, opt) #OLD

            #elif (last_pkt["TCP"].flags == "R"):
            #    #TCP HANDSHAKE
            #    #last_pkt = packets.tcp_handshake() #NEW
            #    ip_pkt, tcp_pkt = packets.tcp_handshake() #OLD

            #    #MQTT CONNECT
            #    #last_pkt = packets.mqtt_connect(last_pkt) #NEW
            #    ip_pkt, tcp_pkt, last_pkt = packets.mqtt_connect(ip_pkt, tcp_pkt, attacker, opt) #OLD

        #else:
        #        
        #    #TCP DISCONNECT
        #    #packets.tcp_disconnect(last_pkt) #NEW
        #    packets.tcp_disconnect(ip_pkt, tcp_pkt, last_pkt) #OLD

        #    #TCP HANDSHAKE
        #    #last_pkt = packets.tcp_handshake() #NEW
        #    ip_pkt, tcp_pkt, last_pkt = packets.tcp_handshake() #OLD

        #    #MQTT CONNECT
        #    #last_pkt = packets.mqtt_connect(last_pkt) #NEW
        #    ip_pkt, tcp_pkt, last_pkt = packets.mqtt_connect(ip_pkt, tcp_pkt, last_pkt, attacker, opt) #OLD
        
    #MQTT DISCONNECT 
    #last_pkt = packets.mqtt_disconnect(last_pkt) #NEW
    ip_pkt, tcp_pkt, last_pkt = packets.mqtt_disconnect(ip_pkt, tcp_pkt, last_pkt, opt) #OLD
    
    #TCP DISCONNECT
    #packets.tcp_disconnect(last_pkt) #NEW
    packets.tcp_disconnect(ip_pkt, tcp_pkt, last_pkt) #OLD

    #READ FILES FROM INPUT DIRECTORY
            #files = os.listdir("./inputs")
        
            #for file in files:
            #    input = open(os.path.join("./inputs", file), "r")
            #    print(input.read())



if __name__ == '__main__':
    packets.check_arguments(argv)
    main(argv[1:])
