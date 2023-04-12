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



from scapy.contrib.mqtt import *
from scapy.all import *
import random
import packets
import grammar

from grammar5 import mqttgram5

#def manual_input():
#    string = input("Enter an input")
#    return string

def random_fuzzer(): #FOR TOPIC OF SUBSCRIBE AND PUBLISH PACKETS ONLY!
    string=""
    length = random.randrange(0, 100 + 1) # automatically calculate the length of the string
    for i in range(0, length):
       string += chr(random.randrange(32, 64)) # Min 0 Max 1114111
       if (string[-1] == "+") or (string[-1] == "#"): string = string[:-1] #TOPIC can not have "#" or "+", thus this assert was added. Message can though.
    return string

def grammar_fuzzer(term):

    #term = "<start>"
    payload_length=0
    packet_identifier=0
    
    while len(grammar.nonterminals(term)) > 0:
        symbol_to_expand = random.choice(grammar.nonterminals(term))
        expansions = grammar.MQTT_GRAMMAR[symbol_to_expand]
        expansion = random.choice(expansions)
        new_term = term.replace(symbol_to_expand, expansion, 1)
       
        #IF STATEMENT ADDED TO SPECIFY EXACTLY THE TOPIC LENGTH, AND THUS RECOGNIZE THE PAYLOAD CORRECTLY
        if "<message>" in expansion:
            payload_length+=1
        elif "<packet-identifier>" in expansion:
            packet_identifier=2

        if len(grammar.nonterminals(new_term)) < 50: #was  < 10. needed to modify for connect
            term = new_term
            #print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= 100:
                raise ExpansionError("Cannot expand " + repr(term))

    #########
    substr = re.findall(r'\\n\\n(.*)', term)
    if len(substr) > 0:
        fields = re.split(r'\\n\\n', substr[0])
        #print(fields)

        for field in fields:
            field_encoded = field.encode('utf-8')
            field_bytes = bytes(map(ord, field_encoded.decode('unicode-escape')))
            
            if term[2] == "3" and field == fields[-1]: #Check whether it is a PUBLISH packet
            #IF STATEMENT ADDED TO SPECIFY EXACTLY THE TOPIC LENGTH, AND THUS RECOGNIZE THE PAYLOAD CORRECTLY
                field_length = struct.pack(">H", len(field_bytes) - payload_length - packet_identifier)

            elif term[2] == "8":
                field_length = struct.pack(">H", len(field_bytes) - 1)# Subtract topic - QoS length

            else:
                field_length = struct.pack(">H", len(field_bytes))



            field_length_bytes = field_length.decode("utf-8") 
            term = term.replace(r'\n\n', field_length_bytes, 1)

    term_bytes = term.encode('utf-8')
    packet = bytes(map(ord, term_bytes.decode('unicode-escape')))
    m = MQTT(packet)
    m = grammar.remaining_length(m)
    #print(m)

    return m


def grammar5_fuzzer(term):
    
    payload_length=0
    packet_identifier=0
    while len(grammar.nonterminals(term)) > 0:
        symbol_to_expand = random.choice(grammar.nonterminals(term))
        expansions = mqttgram5.MQTT5_GRAMMAR[symbol_to_expand]
        expansion = random.choice(expansions)
        new_term = term.replace(symbol_to_expand, expansion, 1)
       
        #IF STATEMENT ADDED TO SPECIFY EXACTLY THE TOPIC LENGTH, AND THUS RECOGNIZE THE PAYLOAD CORRECTLY
        if "<message>" in expansion:
            payload_length+=1
        elif "<packet-identifier>" in expansion:
            packet_identifier=2

        if len(grammar.nonterminals(new_term)) < 50: #was  < 10. needed to modify for connect
            term = new_term
            #print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            #print(len(nonterminals(term)))
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= 100:
                raise ExpansionError("Cannot expand " + repr(term))

    properties = None
    substr = re.findall(r'\\n\\n(.*)', term)
    if len(substr) > 0:
        fields = re.split(r'\\n\\n', substr[0])

        for field in fields:
            unsplit_field = field

            #FOR MQTT5
            if len(re.findall(r'\\p', field)) > 0:  #WORKS FOR PUBLISH AND CONNECT PACKETS
                properties = re.split(r'\\p', field)[1]
                field = re.split(r'\\p', field)[0] #OLD
                if len(re.findall(r'\\r\\r', properties)) > 0: 
                    aproperty = re.split(r'\\r\\r', properties)[1:] #OLD...!!!
                    for prop in aproperty:
                        prop_encoded = prop.encode('utf-8')
                        prop_bytes = bytes(map(ord, prop_encoded.decode('unicode-escape')))
                        prop_field_length = len(prop_bytes)
                        if len(aproperty) > 1 and prop == aproperty[-1]:
                            prop_length = struct.pack(">H", prop_field_length-payload_length) #WORKS FOR PUBLISH AND CONNECT PACKETS
                        else:
                            prop_length = struct.pack(">H", prop_field_length) #WORKS FOR PUBLISH AND CONNECT PACKETS
                        prop_length_bytes = prop_length.decode('utf-8') 
                        term = term.replace(r'\r\r', prop_length_bytes, 1)
                aproperty_encoded = properties.encode('utf-8')
                aproperty_bytes = bytes(map(ord, aproperty_encoded.decode('unicode-escape')))
                aproperty_field_length = len(aproperty_bytes)
                aproperty_length = struct.pack("B", aproperty_field_length-payload_length) #WORKS FOR PUBLISH AND CONNECT PACKETS
                aproperty_length_bytes = aproperty_length.decode('utf-8') 
            elif len(re.findall(r'\\p', term)) > 0: #FOR SUBSCRIBE PACKETS
                properties = re.findall(r'\\p(.+?)\\n\\n', term)
                if len(re.findall(r'\\r\\r', properties[0])) > 0: 
                    aproperty = re.split(r'\\r\\r', properties[0])[1:]#OLD...!!!
                    for prop in aproperty:
                        prop_encoded = prop.encode('utf-8')#OLD...!!!
                        prop_bytes = bytes(map(ord, prop_encoded.decode('unicode-escape')))
                        prop_field_length = len(prop_bytes)
                        prop_length = struct.pack(">H", prop_field_length) #WORKS FOR PUBLISH AND CONNECT PACKETS
                        prop_length_bytes = prop_length.decode('utf-8') 
                        term = term.replace(r'\r\r', prop_length_bytes, 1)
                for aproperty in properties:
                    aproperty_encoded = aproperty.encode('utf-8')
                    aproperty_bytes = bytes(map(ord, aproperty_encoded.decode('unicode-escape')))
                    aproperty_field_length = len(aproperty_bytes)
                    aproperty_length = struct.pack("B", aproperty_field_length) ##FOR SUBSCRIBE PACKETS
                    aproperty_length_bytes = aproperty_length.decode('utf-8') 
            else:
                aproperty_field_length=1 #PROPERTY-0 DOES NOT NEED TO CALCULATE LENGTH

            field_encoded = field.encode('utf-8')
            field_bytes = bytes(map(ord, field_encoded.decode('unicode-escape')))
            
            if term[2] == "3" and unsplit_field == fields[-1]: #Check whether it is a PUBLISH packet
                if aproperty_field_length > 1: #IF IT IS NOT PROPERTY-0, THEN DO NOT SUBSTRACT THE LENGTH SINCE IT WILL NOT BE IN THE FIELD VARIABLE
                    flength = len(field_bytes) - packet_identifier
                elif aproperty_field_length == 1:
                    flength = len(field_bytes) - packet_identifier - aproperty_field_length - payload_length
                field_length = struct.pack(">H", flength)

            elif term[2] == "8":
                field_length = struct.pack(">H", len(field_bytes) - 1)# Subtract topic - QoS length

            else:
                field_length = struct.pack(">H", len(field_bytes))

            field_length_bytes = field_length.decode("utf-8") 
            term = term.replace(r'\n\n', field_length_bytes, 1)
            if properties is not None and len(properties) > 0: 
                term = term.replace(r'\p', aproperty_length_bytes, 1)
                properties = None

    elif len(re.findall(r'\\p', term)) > 0:
        properties = re.findall(r'\\p(.*)', term) 
        if len(re.findall(r'\\r\\r', properties[0])) > 0: 
            aproperty = re.split(r'\\r\\r', properties[0])[1:]
            for prop in aproperty:
                prop_encoded = prop.encode('utf-8')
                prop_bytes = bytes(map(ord, prop_encoded.decode('unicode-escape')))
                prop_field_length = len(prop_bytes)
                prop_length = struct.pack(">H", prop_field_length) #WORKS FOR PUBLISH AND CONNECT PACKETS
                prop_length_bytes = prop_length.decode('utf-8') 
                term = term.replace(r'\r\r', prop_length_bytes, 1)
        for aproperty in properties:
            aproperty_encoded = aproperty.encode('utf-8')
            aproperty_bytes = bytes(map(ord, aproperty_encoded.decode('unicode-escape')))
            aproperty_field_length = len(aproperty_bytes)
            aproperty_length = struct.pack("B", aproperty_field_length) ##FOR SUBSCRIBE PACKETS
            aproperty_length_bytes = aproperty_length.decode('utf-8') 
            term = term.replace(r'\p', aproperty_length_bytes, 1) #ALSO REPEATED

    term_bytes = term.encode('utf-8')
    packet = bytes(map(ord, term_bytes.decode('unicode-escape')))
    m = MQTT(packet)
    m = grammar.remaining_length(m)
    return m

#MAYBE ADD A FUNCTION TO READ CRAFTED INPUTS FROM FILES/PACKETS

if __name__ == '__main__':
    packets.usage()
