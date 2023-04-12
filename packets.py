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



from random import randint
from scapy.all import *
from scapy.contrib.mqtt import *
import modes

mqtt_broker_ip = '192.168.33.20'
#mqtt_broker_ip = '192.168.33.40'

mqtt_broker_port = 1883
#host_port = 1024
#host_port = RandShort()._fix() #CHOOSE RANDOM PORT
host_port = randint(1024, 60000) #CHOOSE RANDOM PORT

#packet_length = {
#    
#    0 : 0, #TCPACK
#    2 : 4, #CONACK
#    4 : 4, #PUBACK
#    5 : 4, #PUBREC
#    7 : 4, #PUBCOMP
#    9 : 5, #SUBACK
#    11: 4, #UNSUBACK
#    13: 2, #PINGRESP
#}

qos_lvls = [0, 1, 2]

def usage():

    print("""python3 fuzz.py <MODE> <ARGUMENT>
    Random Mode: -r <attacker>
    Grammar Mode: -g
    Grammar 5 Mode: -v
    Hybrid Grammar Mode (MQTT 3.1.1 and 5.0 Standard): -h
    """)

    exit(2)

def check_arguments(argv):

    assert len(argv) != 1, usage()

    assert (
            argv[1] == "-r" and len(argv) == 3
            ) or (
                    argv[1] == "-g" and len(argv) == 2
                    ) or (
			    argv[1] == "-v" and len(argv) == 2
			    ) or (
				    argv[1] == "-h" and len(argv) == 2
				    ), \
					usage()
    assert (
            argv[1] == "-r"
            ) or (
                    argv[1] == "-g"
                    ) or (
			    argv[1] == "-v"
			    ) or (
				    argv[1] == "-h"
				    ), \
					usage()



def tcp_handshake():

    global host_port #PORT OF HOST MACHINE
    host_port+=2

    i = IP()
    i.dst = mqtt_broker_ip
    i.src = "192.168.33.1"

    t = TCP()
    t.dport = 1883
    #t.sport = RandShort()._fix()
    t.sport = host_port
    t.flags = "S"

    while(True):
        SYNACK = sr1(i/t, timeout=0.1, retry=3)
        if not SYNACK: 
            #t.sport = RandShort()._fix()
            t.sport = host_port
            continue
        else:
            break

    t.flags = "A"
    t.seq = SYNACK.ack
    t.ack = SYNACK.seq + 1

    #ACK = i/t #NEW
    #send(ACK) #NEW
    #return ACK #NEW

    send(i/t) #OLD
    return i, t, SYNACK #OLD

def mqtt_random(i, t, lp, mode):

    if mode == "-g": pkts = ["<CONNACK>", "<SUBACK>", "<UNSUBACK>", "<PINGRESP>", "<PUBCOMP>", "<PUBREC>", "<PUBREL>", "<PUBACK>"] #FOR MQTT 3.1.1
    if mode == "-v": pkts = ["<CONNACK>", "<SUBACK>", "<UNSUBACK>", "<PINGRESP>", "<PUBCOMP>", "<PUBREC>", "<PUBREL>", "<PUBACK>", "<AUTH>"] #FOR MQTT 5.0

    t.flags = "PA"
    t.seq = lp.ack

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0
#try
    if mode == "-g" or mode == "-v":
        while(True):
            try:
                if mode == "-g": m = modes.grammar_fuzzer(choice(pkts))
                if mode == "-v": m = modes.grammar5_fuzzer(choice(pkts))
            except UnicodeDecodeError:
                #return None, None, None #TODO: ADDED BECAUSE IT HAD AN ERROR WITH THE GRAMMAR BECAUSE OF / FOR MULTIPLE HIERARCHY
                #return i, t, None
                #lp[TCP].flags = "FA"
                #return i, t, lp
                continue
            break

    ans, unans = sr(i/t/m, multi=1, timeout=0.1, retry=3)

    try:
        answer = ans[-1][-1] #Tried with "-1" as the index instead of "1"
    except IndexError:
        lp[TCP].flags = "FA"
        #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        return i, t, lp

    return i, t, answer

def mqtt_pubcomp(i, t, lp, mode):

    t.flags = "PA"
    t.seq = lp.ack #OLD

    if lp.haslayer(MQTTPubrel) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTTPubrel) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        return i, t, lp #IF PACKET IS RESET RETURN

    if mode == "-g" or mode == "-v":
        if mode == "-g": m = modes.grammar_fuzzer("<PUBCOMP>")
        if mode == "-v": m = modes.grammar5_fuzzer("<PUBCOMP>")
        m.msgid = lp.msgid
        pubcomp_pkt = i/t/m

    ans, unans = sr(pubcomp_pkt, multi=1, timeout=0.1, retry=3)
    try:
        PUBCOMP_ACK = ans[-1][-1] #Tried with "-1" as the index instead of "1"
    except IndexError:
        lp[TCP].flags = "FA"
        #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        return i, t, lp

    #if PUBCOMP.haslayer(MQTTPubcomp) == 0: return i, t, PUBCOMP 
    #i, t, lp = mqtt_pubcomp(i, t, PUBREL, mode)
    
    return i, t, PUBCOMP_ACK

def mqtt_pubrec(i, t, lp, mode):

    t.flags = "PA"
    t.seq = lp.ack #OLD

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])

    if mode == "-g" or mode == "-v":
        if mode == "-g": m = modes.grammar_fuzzer("<PUBREC>")
        if mode == "-v": m = modes.grammar5_fuzzer("<PUBREC>")
        m.msgid = lp.msgid
        pubrec_pkt = i/t/m

    ans, unans = sr(pubrec_pkt, multi=1, timeout=0.1, retry=3)
    try:
        PUBREL = ans[-1][-1] #Tried with "-1" as the index instead of "1"
    except IndexError:
        lp[TCP].flags = "FA"
        #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        return i, t, lp

    #if PUBREL.haslayer(MQTTPubrel) == 0: return i, t, PUBREL 
    
    return i, t, PUBREL

def mqtt_puback(i, t, lp, mode):

    t.flags = "PA"
    t.seq = lp.ack #OLD

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])

    if mode == "-g" or mode == "-v":
        if mode == "-g": m = modes.grammar_fuzzer("<PUBACK>")
        if mode == "-v": m = modes.grammar5_fuzzer("<PUBACK>")
        m.msgid = lp.msgid
        puback_pkt = i/t/m

    ans, unans = sr(puback_pkt, multi=1, timeout=0.1, retry=3)
    
    try:
        PUBACK_ACK = ans[-1][-1] #Tried with "-1" as the index instead of "1"
    except IndexError:
        lp[TCP].flags = "FA"
        #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        return i, t, lp

    return i, t, PUBACK_ACK

def respond_publish(i, t, PUBLISH, mode):

    if PUBLISH.QOS == 0:
        t.flags = "A"
        t.seq = PUBLISH.ack

        if PUBLISH.haslayer(Padding): 
            t.ack = PUBLISH.seq + (len(PUBLISH[MQTT]) - len(PUBLISH[Padding]))
        else:
            t.ack = PUBLISH.seq + len(PUBLISH[MQTT])
       
        ACK = i/t
        PUBLISH_ACK = sr1(ACK, timeout=0.1)

        if PUBLISH_ACK is None:
            #ACK[TCP].flags = "FA"
            #return i, t, ACK
            return i, t, PUBLISH
        else:
            return i, t, PUBLISH_ACK

        #try:
        #    PUBLISH_ACK = ans[-1][-1] #Tried with "-1" as the index instead of "1"
        #except IndexError:
        #    ACK[TCP].flags = "FA"
            #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        #    return i, t, ACK

        #return i, t, PUBLISH_ACK

    elif PUBLISH.QOS == 1:
            i, t, PUBACK_ACK = mqtt_puback(i, t, PUBLISH, mode) 
            return i, t, PUBACK_ACK
    
    elif PUBLISH.QOS == 2:
            i, t, PUBREL = mqtt_pubrec(i, t, PUBLISH, mode) #TODONEW
            i, t, PUBCOMP_ACK = mqtt_pubcomp(i, t, PUBREL, mode)
            return i, t, PUBCOMP_ACK


#def mqtt_connect(ip_tcp): #NEW
def mqtt_connect(i, t, lp, attacker, mode):

    
    #ip_tcp["TCP"].flags = "PA" #NEW
    
   # try:
    t.flags = "PA" #OLD
    #except AttributeError:
    #    return None, None, None #TODO: ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR

    if mode == "-r":
    
        mcon = MQTTConnect()
        mcon.protoname = "MQTT"
        mcon.length = 4
        mcon.protolevel = 4
        mcon.clientId = attacker
        mcon.clientIdlen = len(attacker)
        mcon.cleansess = 1
        mcon.klive = 60

        #connect_pkt = ip_tcp/MQTT()/mcon #NEW
        connect_pkt = i/t/MQTT()/mcon #OLD

    elif mode == "-g" or mode == "-v":

        if mode == "-g": m = modes.grammar_fuzzer("<CONNECT>")
        if mode == "-v": m = modes.grammar5_fuzzer("<CONNECT>")
        connect_pkt = i/t/m

    ans, unans = sr(connect_pkt, multi=1, timeout=0.1, retry=3)
    try:
        CONACK = ans[-1][-1] #Tried with "-1" as the index instead of "1"
    except IndexError:
        lp[TCP].flags = "FA"
        #return None, None, None #TODO ADDED TRY BECAUSE IT HAVE ERROR WITH GRAMMAR
        return i, t, lp
        
    if CONACK.haslayer(MQTTConnack) == 0: 
        CONACK[TCP].flags = "FA"
        return i, t, CONACK #TODO: ADDED IN ORER TO CLOSE CONNECTION IF RECEIVING SOMETHING OTHER THAN CONACK

    #ACK = ip_tcp #NEW
    #ACK["TCP"].flags = "A" #NEW
    t.flags = "A" #OLD
    
    #ACK["TCP"].seq = CONACK.ack #NEW
    t.seq = CONACK.ack #OLD
    
    #ACK["TCP"].ack = CONACK.seq + packet_length[CONACK.type] #NEW

    #try:
    #    t.ack = CONACK.seq + packet_length[CONACK.type] #OLD
    #except AttributeError:
    #    return None, None, None#TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR.

    if CONACK.haslayer(MQTT) and CONACK.haslayer(Padding): 
        t.ack = CONACK.seq + (len(CONACK[MQTT]) - len(CONACK[Padding]))
    elif CONACK.haslayer(MQTT) and CONACK.haslayer(Padding) == 0:
        t.ack = CONACK.seq + len(CONACK[MQTT])
    else:
        t.ack = CONACK.seq + 0

    #t.ack = CONACK.seq + (len(CONACK[MQTT]) - len(CONACK[Padding]))  #OLD #TODO
    #send(ACK) #NEW
    #return ACK #NEW

    #send(i/t) #OLD
    #CONACK_ACK = sr1(i/t, timeout=0.1) #TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY
    PUBLISH = sr1(i/t, timeout=0.1)

    if not PUBLISH:
        return i, t, CONACK
    else:
        if PUBLISH.haslayer(MQTTPublish):
            i ,t, lp = respond_publish(i, t, PUBLISH, mode)
            return i, t, lp
        if PUBLISH.haslayer(MQTTPubrel):
            i, t, lp = mqtt_pubcomp(i, t, PUBLISH, mode)
            return i, t, lp
            #WRITE LINE TO VERIFY IF IT IS QOS1
            #if PUBLISH.QOS == 1: 
            #    i, t, lp = mqtt_puback(i, t, PUBLISH, mode) 
            #    return i, t, lp
            ##WRITE LINE TO VERIFY IF IT IS QOS2
            #if PUBLISH.QOS == 2: #TODONEW
            #    i, t, PUBREL = mqtt_pubrec(i, t, PUBLISH, mode) #TODONEW
            #    i, t, PUBCOMP_ACK = mqtt_pubcomp(i, t, PUBREL, mode)
            #    return i, t, PUBCOMP_ACK
            
    #if CONACK_ACK is None: 
    #    return i, t, CONACK#TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY
    #else: 
    #    return i, t, CONACK_ACK #TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY

    #return i, t, CONACK #OLD

#def mqtt_publish(ip_tcp): #NEW
def mqtt_publish(i, t, lp, mode):


    #ip_tcp["TCP"].flags = "PA" #NEW
    
    #try:
    t.flags = "PA" #OLD
    #except AttributeError:
        #return None, None, None #TODO ADDED TRY BECAUSE IT GAVE ERROR WITH GRAMMAR
    #    return i, t, None


    #ip_tcp["TCP"].seq = ip_tcp["TCP"].ack #NEW
    t.seq = lp.ack #OLD
    
    #try: #OLD
    #    #ip_tcp["TCP"].ack = ip_tcp["TCP"].seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[lp.type] #OLD
    #except AttributeError: #OLD
    #    #ip_tcp.ack = ip_tcp.seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[0] #OLD
    #except KeyError: #OLD
    #    #return None #NEW
    #    return None, None, None #OLD

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    if mode == "-r":
        mpub = MQTTPublish()
        mpub.topic = modes.random_fuzzer()
        mpub.value = modes.random_fuzzer()
        random_qos_lvl=choice(qos_lvls)

        #publish_pkt = ip_tcp/MQTT()/mpub #NEW
        publish_pkt = i/t/MQTT(QOS=random_qos_lvl)/mpub #OLD
        if (random_qos_lvl > 0): publish_pkt.msgid=RandShort()._fix()

    elif mode == "-g" or mode == "-v":
        while(True):
            try:
                if mode == "-g": m = modes.grammar_fuzzer("<PUBLISH>")
                if mode == "-v": m = modes.grammar5_fuzzer("<PUBLISH>")
            except UnicodeDecodeError:
                #return None, None, None #TODO: ADDED BECAUSE IT HAD AN ERROR WITH THE GRAMMAR BECAUSE OF / FOR MULTIPLE HIERARCHY
                #return i, t, None
                #lp[TCP].flags = "FA"
                #return i, t, lp
                continue
            break

        publish_pkt = i/t/m #OLD

    ans, unans = sr(publish_pkt, multi=1, timeout=0.1, retry=3)

    try:
        ACK = ans[-1][-1] # FOR QOS0 ONLY
    except IndexError:
        #return None #NEW
        #return None, None, None #OLD
        #return i, t, None #OLD
        publish_pkt[TCP].flags = "FA"
        return i, t, publish_pkt

    #CHECK IF PACKET RECEIVED IS A PUBLISH
    if ACK.haslayer(MQTTPublish): 
        #i ,t, lp = respond_publish(i, t, ACK, mode)
        i ,t, ACK = respond_publish(i, t, ACK, mode)

    #if (random_qos_lvl == 0):
    if (publish_pkt.QOS == 0):

        #if ACK.haslayer(MQTTPublish): 
        #  i ,t, lp = respond_publish(i, t, ACK, mode)
          #return i, t, lp #YOU RECEIVE NO ANSWER ..THATS WHY IT GAVE ERROR AND I COMMENTED IT.

        return i, t, ACK #OLD

    #elif (random_qos_lvl == 1):
    elif (publish_pkt.QOS == 1):

        if ACK.haslayer(MQTTPuback) == 0: return i, t, ACK #TODO: ADDED IFNEW TO CLOSE CONNECTION IF SERVER DISCONNECTS AFTER SENDING PUBLISH QOS1 PACKET

        PUBACK = ACK

        t.flags = "A" #OLD 
        t.seq = PUBACK.ack #OLD 

        #try:
        #    t.ack = PUBACK.seq + packet_length[PUBACK.type] #OLD 
        #except AttributeError:
        #    #t.ack = PUBACK.seq + packet_length[0]
        #    return None, None, None
        #except KeyError:
        #    return None, None, None#TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR. IT GIVES ERROR BECAUSE THE BROKER SENDS A PUBLISH TO THE CLIENT AND IT WASNT EXPECTING IT.
       
        if PUBACK.haslayer(MQTT) and PUBACK.haslayer(Padding): 
            t.ack = PUBACK.seq + (len(PUBACK[MQTT]) - len(PUBACK[Padding]))
        elif PUBACK.haslayer(MQTT) and PUBACK.haslayer(Padding) == 0:
            t.ack = PUBACK.seq + len(PUBACK[MQTT])
        else:
            t.ack = PUBACK.seq + 0

        #t.ack = PUBACK.seq + (len(PUBACK[MQTT]) - len(PUBACK[Padding]))#TODOnew: gave error with grammar

        send(i/t) #OLD
        #PUBLISH = sr1(i/t, timeout=0.1)
#if not PUBLISH:
#            return i, t, PUBACK
#        else:
#            if PUBLISH.haslayer(MQTTPublish): 
#                i ,t, lp = respond_publish(i, t, ACK, mode)
#                return i, t, lp

        return i, t, PUBACK
    
    #elif (random_qos_lvl == 2):
    elif (publish_pkt.QOS == 2):
        
        if ACK.haslayer(MQTTPubrec) == 0: return i, t, ACK #TODO: ADDED IFNEW TO CLOSE CONNECTION IF SERVER DISCONNECTS AFTER SENDING PUBLISH QOS2 PACKET
        PUBREC = ACK

        t.flags = "A" #OLD 
        t.seq = PUBREC.ack #OLD 

        #try:
        #    t.ack = PUBREC.seq + packet_length[PUBREC.type] #OLD 
        #except AttributeError:
        #    #t.ack = PUBACK.seq + packet_length[0]
        #    return None, None, None
        #except KeyError:
        #    return None, None, None#TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR. IT GIVES ERROR BECAUSE THE BROKER SENDS A PUBLISH TO THE CLIENT AND IT WASNT EXPECTING IT.

        if PUBREC.haslayer(MQTT) and PUBREC.haslayer(Padding): 
            t.ack = PUBREC.seq + (len(PUBREC[MQTT]) - len(PUBREC[Padding]))
        elif PUBREC.haslayer(MQTT) and PUBREC.haslayer(Padding) == 0:
            t.ack = PUBREC.seq + len(PUBREC[MQTT])
        else:
            t.ack = PUBREC.seq + 0

        #t.ack = PUBREC.seq + (len(PUBREC[MQTT]) - len(PUBREC[Padding]))

        send(i/t) #OLD #SENDING ACK

        #SEND PUBREL
        if mode == "-r":
            mpubrel = MQTTPubrel()
            mpubrel.msgid = publish_pkt.msgid
            pubrel_pkt = i/t/MQTT(QOS=1)/mpubrel #OLD

        elif mode == "-g" or mode == "-v":
            if mode == "-g": m = modes.grammar_fuzzer("<PUBREL>")
            if mode == "-v": m = modes.grammar5_fuzzer("<PUBREL>")
            pubrel_pkt = i/t/m #OLD
        
        ans, unans = sr(pubrel_pkt, multi=1, timeout=0.1, retry=3)

        try:
            PUBCOMP = ans[-1][-1] # FOR QOS0 ONLY
        except IndexError:
            #return None #NEW
            #return None, None, None #OLD
            pubrel_pkt[TCP].flags = "FA"
            return i, t, pubrel_pkt

        if PUBCOMP.haslayer(MQTTPubcomp) == 0: return i, t, PUBCOMP #TODO:

        t.flags = "A" #OLD 
        t.seq = PUBCOMP.ack #OLD 

        #try:
        #    t.ack = PUBCOMP.seq + packet_length[PUBCOMP.type] #OLD 
        #except AttributeError:
        #    #t.ack = PUBACK.seq + packet_length[0]
        #    return None, None, None

        if PUBCOMP.haslayer(MQTT) and PUBCOMP.haslayer(Padding): 
            t.ack = PUBCOMP.seq + (len(PUBCOMP[MQTT]) - len(PUBCOMP[Padding]))
        elif PUBCOMP.haslayer(MQTT) and PUBCOMP.haslayer(Padding) == 0:
            t.ack = PUBCOMP.seq + len(PUBCOMP[MQTT])
        else:
            t.ack = PUBCOMP.seq + 0

        #t.ack = PUBCOMP.seq + (len(PUBCOMP[MQTT]) - len(PUBCOMP[Padding]))

        send(i/t) #OLD
        return i, t, PUBCOMP



#def mqtt_subscribe(ip_tcp): #NEW
def mqtt_subscribe(i, t, lp, mode):
    
    #ip_tcp["TCP"].flags = "PA" #NEW
    
    #try:
    t.flags = "PA" #OLD
    #except AttributeError:
    #    return None, None, None #TODO ADDED TRY BECAUSE IT GAVE AN ERROR WITH GRAMMAR

    #ip_tcp["TCP"].seq = ip_tcp["TCP"].ack #NEW
    t.seq = lp.ack #OLD
    
    #try:
    #    #ip_tcp["TCP"].ack = ip_tcp["TCP"].seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[lp.type] #OLD
    #except AttributeError: #OLD
    #    #ip_tcp.ack = ip_tcp.seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[0] #OLD
    #except KeyError:
    #    #return None #NEW
    #    return None, None, None #OLD

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    if mode == "-r":
        msub = MQTTSubscribe()
        msub.msgid = 1
        msub.topic = modes.random_fuzzer()

        #subscribe_pkt = ip_tcp/MQTT(type=8, QOS=1)/msub #NEW
        subscribe_pkt = i/t/MQTT(type=8, QOS=1)/msub #OLD

    elif mode == "-g" or mode == "-v":
        while(True):
            try:
                if mode == "-g": m = modes.grammar_fuzzer("<SUBSCRIBE>")
                if mode == "-v": m = modes.grammar5_fuzzer("<SUBSCRIBE>")
            except UnicodeDecodeError:
                #return None, None, None #TODO: THIS WAS ADDED BECAUSE IT CAUSED AN ERROR WITH THE GRAMMER WHEN ADDING / FOR MULTIPLE TOPICS
                #return i, t, None
                #lp[TCP].flags = "FA"
                #return i, t, lp
                continue
            break

        subscribe_pkt = i/t/m #OLD

    ans, unans = sr(subscribe_pkt, multi=1, timeout=0.1, retry=3)# Changed timeout from 0.1 to 0.3 because 0.1 was giving an Index Error in line below
    
    try:
        SUBACK = ans[-1][-1]
    except IndexError:
        #return None #NEW
        #return None, None, None #OLD
        #return i, t, None #OLD
        subscribe_pkt[TCP].flags = "FA"
        return i, t, subscribe_pkt

    #if not SUBACK.haslayer(MQTTSuback): return i, t, SUBACK #TODO ADDED BECAUSE IN ORDER TO FINISH CONNECTION IF RECEIVING SOMETHING OTHER THAN SUBACK

    #ACK = ip_tcp #NEW
    #ACK["TCP"].flags = "A" #NEW
    #ACK["TCP"].seq = SUBACK.ack #NEW
    #ACK["TCP"].ack = SUBACK.seq + packet_length[SUBACK.type] #NEW
    #send(ACK) #NEW
    #return ACK #NEW

    if SUBACK.haslayer(MQTTPublish):
        i, t, lp = respond_publish(i, t, SUBACK, mode)
        return i, t, lp
    else:
        return i, t, SUBACK #OLD

def mqtt_unsubscribe(i, t, lp, mode):

    #try:
    t.flags = "PA" 
    #except AttributeError:
    #    return None, None, None #TODO ADDED TRY BECAUSE IT GAVE AN ERROR WITH GRAMMAR

    t.seq = lp.ack

    #try:
    #    t.ack = lp.seq + packet_length[lp.type] #OLD
    #except AttributeError: #OLD
    #    t.ack = lp.seq + packet_length[0] #OLD
    #except KeyError:
    #    return None, None, None
    
    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    if mode == "-r":
        munsub = MQTTUnsubscribe()
        munsub.msgid = 2
        munsub.topics = [MQTTTopic(topic=modes.random_fuzzer())]
       #m = MQTTUnsubscribe(msgid=2, topics=[MQTTTopic(topic="hello")]) 

        unsubscribe_pkt = i/t/MQTT(type=10, QOS=1)/munsub

    elif mode == "-g" or mode == "-v":
        while(True):
            try:
                if mode == "-g": m = modes.grammar_fuzzer("<UNSUBSCRIBE>")
                if mode == "-v": m = modes.grammar5_fuzzer("<UNSUBSCRIBE>")
            except UnicodeDecodeError:
                #return None, None, None #TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR WHEN ADDING / FOR MULTIPLE TOPIC SUBSCRIPTIONS
                #return i, t, None
                #lp[TCP].flags = "FA"
                #return i, t, lp
                continue
            break

        unsubscribe_pkt = i/t/m #OLD

    ans, unans = sr(unsubscribe_pkt, multi=1, timeout=0.1, retry=3)# Changed timeout from 0.1 to 0.3 because 0.1 was giving an Index Error in line below

    try:
        UNSUBACK = ans[-1][-1] #OLD
        #if ans[-1][-1].haslayer(MQTTUnsuback): UNSUBACK = ans[-1][-1] #TODO:NEWANALYZES IF LAST PACKET RECEIVED WAS UNSUBACK, if NOT finish connection.
    except IndexError:
        #return None #NEW
        #return None, None, None #OLD
        #return i, t, None #OLD
        unsubscribe_pkt[TCP].flags = "FA"
        return i, t, unsubscribe_pkt
       
    if UNSUBACK.haslayer(MQTTPublish):
        i, t, UNSUBACK = respond_publish(i, t, UNSUBACK, mode)
        #return i, t, lp
    #else:
     #   return i, t, SUBACK #OLD

    if UNSUBACK.haslayer(MQTTUnsuback) == 0: return i, t, UNSUBACK #TODO: NEW ADDED TO SEE IF IT CLOSES CONNECTION

    #ACKNOWLEDGING RECEIVING UNSUBACK packet
    t.flags = "A" #OLD 
    t.seq = UNSUBACK.ack #OLD 

    #try:
    #    t.ack = UNSUBACK.seq + packet_length[UNSUBACK.type] #OLD 
    #except AttributeError:
    #    #t.ack = PUBACK.seq + packet_length[0]
    #    return None, None, None
    #except KeyError:
    #    return None, None, None #TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR. IT GIVES ERROR BECAUSE THE BROKER SENDS A PUBLISH TO THE CLIENT AND IT WASNT EXPECTING IT.

    if UNSUBACK.haslayer(MQTT) and UNSUBACK.haslayer(Padding): 
        t.ack = UNSUBACK.seq + (len(UNSUBACK[MQTT]) - len(UNSUBACK[Padding]))
    elif UNSUBACK.haslayer(MQTT) and UNSUBACK.haslayer(Padding) == 0:
        t.ack = UNSUBACK.seq + len(UNSUBACK[MQTT])
    else:
        t.ack = UNSUBACK.seq + 0

    #t.ack = UNSUBACK.seq + (len(UNSUBACK[MQTT]) - len(UNSUBACK[Padding]))

    send(i/t) #OLD
    return i, t, UNSUBACK #OLD
    #UNSUBACK_ACK = sr1(i/t, timeout=0.1) #TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY

    #if UNSUBACK_ACK is None: 
    #    return i, t, UNSUBACK#TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY
    #else: 
    #    return i, t, UNSUBACK_ACK#TODO: ADDED TO SEE IF IT FIXES ERROR WHERE CONNECTION WAS NOT CLOSED IMMEDIATELY

def mqtt_ping(i, t, lp, mode):

    #try:
    t.flags = "PA" 
    #except AttributeError:
    #    return None, None, None #TODO ADDED TRY BECAUSE IT GAVE AN ERROR WITH GRAMMAR
    
    t.seq = lp.ack

    #try:
    #    t.ack = lp.seq + packet_length[lp.type] #OLD
    #except AttributeError: #OLD
    #    t.ack = lp.seq + packet_length[0] #OLD
    #except KeyError:
    #    return None, None, None

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    if mode == "-r":
        pingreq_pkt = i/t/MQTT(type=12)

    elif mode == "-g" or mode == "-v":
        if mode == "-g": m = modes.grammar_fuzzer("<PINGREQ>")
        if mode == "-v": m = modes.grammar5_fuzzer("<PINGREQ>")
        pingreq_pkt = i/t/m #OLD

    ans, unans = sr(pingreq_pkt, multi=1, timeout=0.1, retry=3)# Changed timeout from 0.1 to 0.3 because 0.1 was giving an Index Error in line below
    
    try:
        PINGRESP = ans[-1][-1]
    except IndexError:
        #return None #NEW
        #return None, None, None #OLD
        #return i, t, None
        pingreq_pkt[TCP].flags = "FA"
        return i, t, pingreq_pkt

    if PINGRESP.haslayer(MQTTPublish):
        i, t, PINGRESP = respond_publish(i, t, PINGRESP, mode)
        #return i, t, lp
    #else:
    #    return i, t, PINGRESP #OLD

    if PINGRESP.haslayer(MQTT) == 0: 
        PINGRESP[TCP].flags = "FA"
        return i, t, PINGRESP #TODO: ADDED IN ORER TO CLOSE CONNECTION IF RECEIVING SOMETHING OTHER THAN CONACK

    #if PINGRESP.haslayer(MQTT) == 1: #TODO
    #    if PINGRESP.type != 13: 
    #        return i, t, ans[-1][-1]#TODO: ADDED BECAUSE OF GRAMMAR
    #else:#TODO
    #    return i, t, ans[-1][-1]#TODO

    #ACKNOWLEDGING RECEIVING PINGRESP packet
    t.flags = "A" #OLD 
    t.seq = PINGRESP.ack #OLD 

    #try:
    #    t.ack = PINGRESP.seq + packet_length[PINGRESP.type] #OLD 
    #except AttributeError:
    #    #t.ack = PUBACK.seq + packet_length[0]
    #    return None, None, None
    #except KeyError:
    #    return None, None, None#TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR. IT GIVES ERROR BECAUSE THE BROKER SENDS A PUBLISH TO THE CLIENT AND IT WASNT EXPECTING IT.
    
    if PINGRESP.haslayer(MQTT) and PINGRESP.haslayer(Padding): 
        t.ack = PINGRESP.seq + (len(PINGRESP[MQTT]) - len(PINGRESP[Padding]))
    elif PINGRESP.haslayer(MQTT) and PINGRESP.haslayer(Padding) == 0:
        t.ack = PINGRESP.seq + len(PINGRESP[MQTT])
    else:
        t.ack = PINGRESP.seq + 0

    #t.ack = PINGRESP.seq + (len(PINGRESP[MQTT]) - len(PINGRESP[Padding]))

    send(i/t) #OLD
    return i, t, PINGRESP


    

#def mqtt_disconnect(ip_tcp): #NEW
def mqtt_disconnect(i, t, lp, mode):

    #ip_tcp["TCP"].flags = "PA" #NEW
    
    #try:
    t.flags = "FA" #OLD
    #except AttributeError:
    #    return None, None, None #TODO ADDDED TRY BECAUSE IT GAVE AN ERROR WITH GRAMMAR

    #ip_tcp["TCP"].seq = ip_tcp["TCP"].ack #NEW
    t.seq = lp.ack #OLD

    #try:
    #    #ip_tcp["TCP"].ack = ip_tcp["TCP"].seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[lp.type] #OLD
    #except AttributeError: #OLD
    #    #ip_tcp.ack = ip_tcp.seq + packet_length[0] #NEW
    #    t.ack = lp.seq + packet_length[0] #OLD
    #except KeyError: 
    #    return None, None, None #TODO: THIS WAS ADDED BECAUSE GAVE ERROR WITH GRAMMAR. IT GIVES ERROR BECAUSE THE BROKER SENDS A PUBLISH TO THE CLIENT AND IT WASNT EXPECTING IT.
    
    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    if mode == "-r":
        m = MQTT() #OLD
        m.type = 14 #OLD

    elif mode == "-g":
        m = modes.grammar_fuzzer("<DISCONNECT>")

    elif mode == "-v":
        m = modes.grammar5_fuzzer("<DISCONNECT>")
        
        #DISCONNECT_ACK = ip_tcp/MQTT(type=14) #NEW
        #send(DISCONNECT_ACK) #NEW
        #return ip_tcp #NEW

    #DISCONNECT_ACK = sr1(i/t/m) #OLD
    ans, unans = sr(i/t/m, multi=1, timeout=0.1, retry=3) #TODONEW
    #if any(an[1].haslayer(MQTTPublish) for an in ans): #TODONEW
    #    i ,t, lp = respond_publish(i, t, ans[0][1], mode)
    
    try:
        DISCONNECT_ACK = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

   # if DISCONNECT_ACK.haslayer(MQTTPublish):
   #     i ,t, lp = respond_publish(i, t, DISCONNECT_ACK, mode)
   #     #lp[TCP].flags = "FA"
   #     return i, t, lp
   # elif DISCONNECT_ACK.haslayer(MQTTPubrel):
   #     i, t, lp = mqtt_pubcomp(i, t, DISCONNECT_ACK, mode)
   #     return i, t, lp

    return i, t, DISCONNECT_ACK #OLD

#def tcp_disconnect(ip_tcp): #NEW
def tcp_disconnect(i, t, lp):

    #try:
        #ip_tcp["TCP"].flags = "FA" #NEW
    t.flags = "FA" #OLD
    #except AttributeError:
    #    return None, None, None #TODO: ADDED BECAUSE IT GAVE AN ERROR WITH GRAMMAR
   
    #ip_tcp["TCP"].seq = ip_tcp["TCP"].ack #NEW
    #ip_tcp["TCP"].ack = ip_tcp["TCP"].seq + 1 #NEW
    
    #if lp is not None:
    t.seq = lp.ack #OLD
    t.ack = lp.seq + 1 #OLD
    #else:
    #    t.seq = t.ack
    #    t.ack = t.seq + 1

    #if lp.haslayer(MQTT):
    #    FINACK = sr1(i/t, timeout=0.1)
    #    t.flags = "FA"
    #    t.seq = FINACK.ack
    #    t.ack = FINACK.seq + 1
    #    send(i/t)
    #else:
    #    #send(ip_tcp) #NEW
    send(i/t) #OLD

if __name__ == '__main__':
    usage()
