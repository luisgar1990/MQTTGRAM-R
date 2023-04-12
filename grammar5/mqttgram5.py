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


MQTT5_GRAMMAR = {
        "<start>":
            ["<packets>"],

        "<packets>":
            [
                "<CONNECT>",
                "<CONNACK>",
                "<PUBLISH>",
                "<PUBACK>",
                "<PUBREC>",
                "<PUBREL>",
                "<PUBCOMP>",
                "<SUBSCRIBE>",
                "<SUBACK>",
                "<UNSUBSCRIBE>",
                "<UNSUBACK>",
                "<PINGREQ>",
                "<PINGRESP>",
                "<DISCONNECT>",
                "<AUTH>",
            ],

        "<CONNECT>":#PAYLOAD IS REQUIRED FOR CONNECT PACKETS
        [
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_DEFAULTPAYLOAD><CONNECT_PROPERTY><CONNECT_DEFAULTPAYLOAD>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_WILLFLAG><CONNECT_PROPERTY><CONNECT_PAYLOAD_WILLTOPIC>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG><CONNECT_PROPERTY><CONNECT_PAYLOAD_USERNAME>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_WILLFLAG><CONNECT_PROPERTY><CONNECT_PAYLOAD_USERNAME_WILLTOPIC>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_PASSWORDFLAG><CONNECT_PROPERTY><CONNECT_PAYLOAD_PASSWORD>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_PASSWORDFLAG_WILLFLAG><CONNECT_PROPERTY><CONNECT_PAYLOAD_USERNAME_PASSWORD_WILLTOPIC>',
           ],

        "<CONNECT_VARIABLE_HEADER_FLAGS_DEFAULTPAYLOAD>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-defaultpayload><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-willflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag-willflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_PASSWORDFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-passwordflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_PASSWORDFLAG_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag-passwordflag-willflag><keep-alive>'],

        "<CONNECT_PROPERTY>":
        [
                #r'<property-length><connect-property><property-value>',
                #r'\x00', #DEFAULT CASE
                #r'\x05\x11\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>' #SESSION EXPIRY INTERVAL
                #r'\x03\x21\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>', #RECEIVE MAXIMUM
                #r'\x05\x27\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>' #MAXIMUM PACKET SIZE
                #r'\x03\x22\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>', #TOPIC ALIAS MAXIMUM
                '<property-0>',
                '<property-session-expiry-interval>',
                '<property-receive-maximum>',
                '<property-maximum-packet-size>',
                '<property-topic-alias-maximum>',
                '<property-request-response-information>', #REQUEST PROBLEM INFORMATION
                '<property-request-problem-information>', #REQUEST PROBLEM INFORMATION
        ],

        "<property-0>":
            [r'\x00'],

        "<property-session-expiry-interval>":
            [r'\x05\x11\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'], #SESSION EXPIRY INTERVAL

        "<property-receive-maximum>":
            [r'\x03\x21\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'], #RECEIVE MAXIMUM

        "<property-maximum-packet-size>":
            [r'\x05\x27\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'], #MAXIMUM PACKET SIZE

        "<property-topic-alias-maximum>":
            [r'\x03\x22\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'], #TOPIC ALIAS MAXIMUM

        "<property-request-response-information>":
                [
                        r'\x02\x19\x00', #REQUEST PROBLEM INFORMATION
                        r'\x02\x19\x01' #REQUEST PROBLEM INFORMATION
                ],

        "<property-request-problem-information>":
                [
                        r'\x02\x17\x00', #REQUEST PROBLEM INFORMATION
                        r'\x02\x17\x01' #REQUEST PROBLEM INFORMATION
                ],

        "<CONNECT_DEFAULTPAYLOAD>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id>"],

        "<CONNECT_PAYLOAD_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><will-property><string-length><will-topic><string-length><will-message>"],

        "<will-property>":
            [
                    '<property-will-delay-interval>',
                    '<property-payload-format-indicator>',
                    '<property-message-expiry-interval>',
                    '<property-content-type>', #TODO 
                    '<property-response-topic>', #TODO
                    '<property-correlation-data>', #TODO
                    '<property-user-property>', #TODO

            ],

        "<property-will-delay-interval>":
            [
                    #r'\x05\x18\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'
                    r'\p\x18\x<digit><digit>\x<digit><digit>\x<digit><digit>\x<digit><digit>'
            ], 

        "<property-payload-format-indicator>":
            [
                    r'\p\x01\x00',
                    r'\p\x01\x01',
            ],

        "<property-message-expiry-interval>":
            [
                    r'\p\x02\x<digit><digit>\x<digit><digit>\x<digit><digit>\x<digit><digit>'
            ],

        "<property-utf8-string>":
            [
                    "<utf8-characters><property-utf8-string>",
                    "<utf8-characters>",


            ],

        "<property-content-type>": #TODO
            [
                    #r'\n\x03<utf8-numbers><utf8-numbers><utf8-numbers>'
                    #r'\p\x03\x00\x01\x68',
                    #r'\p\x03\r\r\x68',
                    r'\p\x03\r\r<property-utf8-string>',
            ],

        "<property-response-topic>": #TODO
            [
                    #r'\n\x08<utf8-latin-smallletters><utf8-latin-smallletters>'
                    #r'\p\x08\x00\x01\x68',
                    #r'\p\x08\r\r\x68',
                    r'\p\x08\r\r<property-utf8-string>',
            ],
        
        "<property-correlation-data>": #TODO
            [
                   # r'\n\x09\x00\x01\x68',
                    #r'\p\x09\x00\x01\x68',
                    #r'\p\x09\r\r\x68',
                    r'\p\x09\r\r<property-utf8-string>',

            ],

        "<property-user-property>": #TODO UTF8 STRING PAIR
            [
                    #r'\p\x26\x00\x02\x68\x68\x68\x68',
                    r'\p\x26\r\r<property-utf8-string>\r\r<property-utf8-string>',

            ],

        "<CONNECT_PAYLOAD_USERNAME>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><username>"],

        "<CONNECT_PAYLOAD_USERNAME_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><will-property><string-length><will-topic><string-length><will-message><string-length><username>"],

        "<CONNECT_PAYLOAD_PASSWORD>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><username><string-length><password>"],

        "<CONNECT_PAYLOAD_USERNAME_PASSWORD_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><will-property><string-length><will-topic><string-length><will-message><string-length><username><string-length><password>"],

        "<CONNACK>": #HAS NO PAYLOAD
            [r'\x2<reserved-0>\x02<CONNACK_VARIABLE_HEADER><CONNACK_PROPERTY>'],

        "<CONNACK_VARIABLE_HEADER>":
            [r'<connack-flags><session-present-flag>\x<connect-return-code>'],


        "<connack-flags>":
            [r'\x0'], #MUST BE 0
                
        "<session-present-flag>": #DEPENDS ON CONNECT PACKET (CLEANSESS ENABLED)
            [
                    "0", #NOT ENABLED
                    "1" #ENABLED
            ],

        "<connect-return-code>":
            [
                "00", #SUCCESS
                "80", #UNSPECIFIED ERROR
                "81", #MALFORMED PACKET
                "82", #PROTOCOL ERROR
                "83", #IMPLEMENTATION SPECIFIC ERROR
                "84", #UNSUPPORTED PROTOCOL VERSION
                "85", #CLIENT IDENTIFIER NOT VALID
                "86", #BAD USER NAME OR PASSWORD
                "87", #NOT AUTHORIZED
                "88", #SERVER UNAVAILABLE
                "89", #SERVER BUSY
                "8A", #BANNED
                "8C", #BAD AUTHENTICATION METHOD
                "90", #TOPIC NAME INVALID
                "95", #PACKET TOO LARGE
                "97", #QUOTA EXCEEDED
                "99", #PAYLOAD FORMAT INVALID
                "9A", #RETAIN NOT SUPPORTED
                "9B", #QOS NOT SUPPORTED
                "9C", #USE ANOTHER SERVER
                "9D", #SERVER MOVED
                "9F", #CONNECTION RATE EXCEEDED
            ],
            

        "<CONNACK_PROPERTY>":
        [
                '<property-0>',
                '<property-session-expiry-interval>',
                '<property-receive-maximum>',
                '<property-maximum-qos>',
                '<property-retain-available>',
                '<property-maximum-packet-size>',
                '<property-assigned-client-identifier>', #TODO
                '<property-topic-alias-maximum>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
                '<property-wildcard-subscription-available>',        
                "<property-subscription-identifiers-available>",
                "<property-shared-subscription-available>",
                "<property-server-keep-alive>", #TODO
                '<property-response-information>', #TODO
                '<property-server-reference>', #TODO
                '<property-authentication-method>', #TODO
                '<property-authentication-data>', #TODO
        ],

        "<property-maximum-qos>":
            [
                    r'\p\x24\x00',
                    r'\p\x24\x01',
            ],

        "<property-retain-available>":
            [
                    r'\p\x25\x00', #A VALUE OF 0 MEANS THAT RETAINED MESSAGES ARE UNSUPPORTED
                    r'\p\x25\x01', #A VALUE OF 1 MEANS THAT RETAINED MESSAGES ARE SUPPORTED
            ],

        "<property-assigned-client-identifier>": #TODO
            [
                    #r'\n\x12\x01\x68'
                    #r'\p\x12\x00\x01\x68'
                    #r'\p\x12\r\r\x68'
                    r'\p\x12\r\r<property-utf8-string>',
            ],

        "<property-reason-string>": #TODO
            [
                    #r'\n\x1f\x01\x68'
                    #r'\p\x1f\x00\x01\x68'
                    #r'\p\x1f\r\r\x68'
                    r'\p\x1f\r\r<property-utf8-string>',
            ],

        "<property-wildcard-subscription-available>":
            [
                    r'\p\x28\x00' #TODO A VALUE 0 MEANS THAT WILDCARD SUBSCRIPTIONS ARE NOT SUPPORTED
                    r'\p\x28\x01' #TODO A VALUE 1 MEANS THAT WILDCARD SUBSCRIPTIONS ARE SUPPORTED

            ],

        "<property-subscription-identifiers-available>":
            [
                    r'\p\x29\x00' #TODO A VALUE 0 MEANS THAT SUBSCRIPTION IDENTIFIERS ARE NOT SUPPORTED
                    r'\p\x29\x01' #TODO A VALUE 1 MEANS THAT SUBSCRIPTION IDENTIFIERS ARE SUPPORTED
            ],

        "<property-shared-subscription-available>":
            [
                    r'\p\x2a\x00' #TODO A VALUE 0 MEANS THAT SHARED SUBSCRIPTIONS ARE NOT SUPPORTED
                    r'\p\x2a\x01' #TODO A VALUE 1 MEANS THAT SHARED SUBSCRIPTIONS ARE SUPPORTED
            ],


        "<property-server-keep-alive>": #TODO 
            [
                    r'\p\x13\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'
            ],

        "<property-response-information>": #TODO
            [
                    #r'\p\x1a\x00\x01\x68',
                    #r'\p\x1a\r\r\x68',
                    r'\p\x1a\r\r<property-utf8-string>',

            ],

        "<property-server-reference>": #TODO
            [
                    #r'\p\x1c\x00\x01\x68',
                    #r'\p\x1c\r\r\x68',
                    r'\p\x1c\r\r<property-utf8-string>',
            ],
        
        "<property-authentication-method>": #TODO
            [
                    #r'\p\x15\x00\x01\x68',
                    #r'\p\x15\r\r\x68',
                    r'\p\x15\r\r<property-utf8-string>',
            ],

        "<property-authentication-data>": #TODO
            [
                    #r'\p\x16\x00\x01\x68',
                    #r'\p\x16\r\r\x68',
                    r'\p\x16\r\r<property-utf8-string>',
            ],

        "<PUBLISH>": #CAN HAVE A PAYLOAD LENGTH OF ZERO
        [
            r'\x3<PUBLISH_FIXED_HEADER_QOS0><PUBLISH_VARIABLE_HEADER_QOS0><PUBLISH_PROPERTY>', 
            r'\x3<PUBLISH_FIXED_HEADER_QOS0><PUBLISH_VARIABLE_HEADER_QOS0><PUBLISH_PROPERTY><PUBLISH_PAYLOAD>',
            r'\x3<PUBLISH_FIXED_HEADER_QOS12><PUBLISH_VARIABLE_HEADER_QOS12><PUBLISH_PROPERTY>', 
            r'\x3<PUBLISH_FIXED_HEADER_QOS12><PUBLISH_VARIABLE_HEADER_QOS12><PUBLISH_PROPERTY><PUBLISH_PAYLOAD>'
        ],

        "<PUBLISH_FIXED_HEADER_QOS0>":
        ["<publish-reserved-qos0><remaining-length>"], 

        "<PUBLISH_VARIABLE_HEADER_QOS0>":
        ["<string-length><topic-name>"],

        "<PUBLISH_PROPERTY>":
            [
                '<property-0>', #TODO DONT THINK THIS IS CORRECT. THINK PROPERTY IN PUBLISH PACKETS CAN NOT BE 0
                '<property-payload-format-indicator>',
                '<property-message-expiry-interval>',
                '<property-topic-alias>',
                '<property-response-topic>', #TODO
                '<property-correlation-data>', #TODO
                '<property-user-property>', #TODO
                '<property-subscription-identifier>', #A PUBLISH PACKET SENT FROM A CLIENT TO A SERVER MUST NOT CONTAIN A SUBSCRIPTION IDENTIFIER
                '<property-content-type>', #TODO 
            ],

        "<property-payload-format-indicator>":
            [
                    r'\p\x01\x00', #PAYLOAD IS UNSPECIFIED BYTES
                    r'\p\x01\x01', #PAYLOAD IS UTF8 ENCODED CHARACTER DATA
            ],

        "<property-topic-alias>":
            [
                    r'\p\x23\x<digit><digit>\x<digit><digit>' #INTEGER VALUE, THUS USED DIGITS 
            ],

        "<property-subscription-identifier>": #TODO
            [
                    #r'\n\x0b\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x0<hexdigit>'
                    #r'\p\x0b\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x0<hexdigit>'
                    #r'\p\x0b\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'
                    r'\p\x0b\x0<hexdigit>',
                    #r'\p\x0b\x<hexdigit><hexdigit>\x0<hexdigit>',
                    #r'\p\x0b\x<hexdigit><hexdigit>\x<hexdigit><hexdigit><\x0<hexdigit>',
                    #r'\p\x0b\x<hexdigit><hexdigit>\x<hexdigit><hexdigit><\x<hexdigit><hexdigit>\x0<hexdigit>',
            ],

        "<PUBLISH_FIXED_HEADER_QOS12>":
        ["<publish-reserved-qos12><remaining-length>"], 

        "<PUBLISH_VARIABLE_HEADER_QOS12>":
        ["<string-length><topic-name><packet-identifier>"],

        "<PUBLISH_PAYLOAD>":
            ["<message>"],

        "<PUBACK>": #HAS NO PAYLOAD; SENT ONLY IF QOS=1#
            [r'\x4<reserved-0>\x02<PUBACK_VARIABLE_HEADER><PUBACK_PROPERTY>'],

        "<PUBACK_VARIABLE_HEADER>":
            [r'<packet-identifier>\x<puback-reason-code>'], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<puback-reason-code>":
            [
                    "00", #SUCCESS
                    "10", #NO MATCHING SUBSCRIBERS
                    "80", #UNSPECIFIED ERROR
                    "83", #IMPLEMENTATION SPECIFIC ERROR
                    "87", #NOT AUTHORIZED
                    "90", #TOPIC NAME INVALID
                    "91", #PACKET IDENTIFIER IN USE
                    "97", #QUOTA EXCEEDED
                    "99" #PAYLOAD FORMAT INVALID
            ],

        "<PUBACK_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],

        "<PUBREC>": #HAS NO PAYLOAD; SENT FROM SERVER TO CLIENT IF QOS=2
            [r'\x5<reserved-0>\x02<PUBREC_VARIABLE_HEADER><PUBREC_PROPERTY>'],

        "<PUBREC_VARIABLE_HEADER>":
            [r'<packet-identifier>\x<pubrec-reason-code>'], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<pubrec-reason-code>":
            [
                    "00", #SUCCESS
                    "10", #NO MATCHING SUBSCRIBERS
                    "80", #UNSPECIFIED ERROR
                    "83", #IMPLEMENTATION SPECIFIC ERROR
                    "87", #NOT AUTHORIZED
                    "90", #TOPIC NAME INVALID
                    "91", #PACKET IDENTIFIER IN USE
                    "97", #QUOTA EXCEEDED
                    "99" #PAYLOAD FORMAT INVALID
            ],

        "<PUBREC_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],


        "<PUBREL>": #HAS NO PAYLOAD; SENT ONLY IF QOS=2
            [r'\x6<reserved-2>\x02<PUBREL_VARIABLE_HEADER><PUBREL_PROPERTY>'],

        "<PUBREL_VARIABLE_HEADER>":
            [r'<packet-identifier>\x<pubrel-reason-code>'], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET
        
        "<pubrel-reason-code>":
            [
                    "00", #SUCCESS
                    "92", #PACKET IDENTIFIER NOT FOUND
            ],

        "<PUBREL_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],


        "<PUBCOMP>": #HAS NO PAYLOAD, SENT FROM SERVER TO CLIENT IF QOS=2
            [r'\x7<reserved-0>\x02<PUBCOMP_VARIABLE_HEADER><PUBCOMP_PROPERTY>'],

        "<PUBCOMP_VARIABLE_HEADER>":
            [r'<packet-identifier>\x<pubcomp-reason-code>'], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<pubcomp-reason-code>":
            [
                    "00", #SUCCESS
                    "92", #PACKET IDENTIFIER NOT FOUND
            ],

        "<PUBCOMP_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],


        "<SUBSCRIBE>": 
        #PAYLOAD IS REQUIRED!
        #RESERVED MUST BE SET TO 0,0,1,0 (2) respectively, otherwise server must close connection.
        [r'\x8<reserved-2><remaining-length><SUBSCRIBE_VARIABLE_HEADER><SUBSCRIBE_PROPERTY><SUBSCRIBE_PAYLOAD>'],

        "<SUBSCRIBE_VARIABLE_HEADER>":
            ["<packet-identifier>"],

        "<SUBSCRIBE_PROPERTY>":
            [

                '<property-0>',
                '<property-subscription-identifier>', #TODO
                '<property-user-property>', #TODO

            ],

        "<SUBSCRIBE_PAYLOAD>":#TODO:COULD SUBSCRIBE TO MORE THAN ONE TOPIC AT ONCE
            [
                    "<string-length><topic-name><subscribe-options><SUBSCRIBE_PAYLOAD>", 
                    "<string-length><topic-name><subscribe-options>"
                    ], 

        "<subscribe-options>":
            [
                    r'\x00', #NOTHING
                    r'\x01', #QOS1
                    r'\x02', #QOS2
                    r'\x04', #LOCAL SET
                    r'\x05', #QOS1 LOCAL SET
                    r'\x06', #QOS2 LOCAL SET
                    r'\x08', #RETAIN AS PUBLISHED
                    r'\x09', #RETAIN AS PUBLISHED QOS 1
                    r'\x0a', #RETAIN AS PUBLISHED QOS 2
                    r'\x0c', #RETAIN AS PUBLISHED LOCAL SET
                    r'\x0d', #RETAIN AS PUBLISHED LOCAL SET QOS 1
                    r'\x0e', #RETAIN AS PUBLISHED LOCAL SET QOS 2
                    r'\x10', #RETAIN HANDLING 1
                    
                    r'\x11', #RETAIN HANDLING 1 QOS1
                    r'\x12', #RETAIN HANDLING 1 QOS2
                    r'\x14', #RETAIN HANDLING 1 LOCAL SET
                    r'\x15', #RETAIN HANDLING 1 QOS1 LOCAL SET
                    r'\x16', #RETAIN HANDLING 1 QOS2 LOCAL SET
                    r'\x18', #RETAIN HANDLING 1 RETAIN AS PUBLISHED
                    r'\x19', #RETAIN HANDLING 1 RETAIN AS PUBLISHED QOS 1
                    r'\x1a', #RETAIN HANDLING 1 RETAIN AS PUBLISHED QOS 2
                    r'\x1c', #RETAIN HANDLING 1 RETAIN AS PUBLISHED LOCAL SET
                    r'\x1d', #RETAIN HANDLING 1 RETAIN AS PUBLISHED LOCAL SET QOS 1
                    r'\x1e', #RETAIN HANDLING 1 RETAIN AS PUBLISHED LOCAL SET QOS 2

                    r'\x20', #RETAIN HANDLING 2 : DO NOT SEND MSGS AT SUBSCRIPTION TIME
                    r'\x21', #QOS 1 AND RETAIN HANDLING 2: DO NOT SEND MSGS AT SUBSCRIPTION TIME
                    r'\x22', #QOS 2 AND RETAIN HANDLING: DO NOT SEND MSGS AT SUBSCRIPTION TIME
                    r'\x24', #RETAIN HANDLING 2 LOCAL SET
                    r'\x25', #RETAIN HANDLING 2 QOS1 LOCAL SET
                    r'\x26', #RETAIN HANDLING 2 QOS2 LOCAL SET
                    r'\x28', #RETAIN HANDLING 2 RETAIN AS PUBLISHED
                    r'\x29', #RETAIN HANDLING 2 RETAIN AS PUBLISHED QOS 1
                    r'\x2a', #RETAIN HANDLING 2 RETAIN AS PUBLISHED QOS 2
                    r'\x2c', #RETAIN HANDLING 2 RETAIN AS PUBLISHED LOCAL SET
                    r'\x2d', #RETAIN HANDLING 2 RETAIN AS PUBLISHED LOCAL SET QOS 1
                    r'\x2e', #RETAIN HANDLING 2 RETAIN AS PUBLISHED LOCAL SET QOS 2
            ],


        "<SUBACK>": #PAYLOAD IS REQUIRED!
            [r'\x9<reserved-0><remaining-length><SUBACK_VARIABLE_HEADER><SUBACK_PROPERTY>\x<SUBACK_PAYLOAD>'],
        
        "<SUBACK_VARIABLE_HEADER>":
            ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS SUBSCRIBE PACKET

        "<SUBACK_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],


        "<SUBACK_PAYLOAD>":
            [
                "00", #SUCCESS - MAXIMUM QOS0
                "01", #SUCCESS - MAXIMUM Q0S1
                "02", #SUCCESS - MAXIMUM QOS2
                "80", #UNSPECIFIED ERROR
                "83", #IMPLEMENTATION SPECIFIC ERROR
                "87", #NOT AUTHORIZED
                "8F", #TOPIC FILTER INVALID
                "91", #PACKET IDENTIFIER IN USE
                "97", #QUOTA EXCEEDED
                "9e", #SHARED SUBSCRIPTIONS NOT SUPPORTED
                "a1", #SUBSCRIPTION IDENTIFIERS NOT SUPPORTED
                "a2", #WILDCARD SUBSCRIPTIONS NOT SUPPORTED
            ],

        "<UNSUBSCRIBE>": 
        #PAYLOAD IS REQUIRED!
        #RESERVED MUST BE SET TO 0,0,1,0 respectively, otherwise server must close connection.
        [r'\xa<reserved-2><remaining-length><UNSUBSCRIBE_VARIABLE_HEADER><UNSUBSCRIBE_PROPERTY><UNSUBSCRIBE_PAYLOAD>'],

        "<UNSUBSCRIBE_VARIABLE_HEADER>":
            ["<packet-identifier>"],

        "<UNSUBSCRIBE_PROPERTY>":
            [
                '<property-0>',
                '<property-user-property>', #TODO
            ],


        "<UNSUBSCRIBE_PAYLOAD>":
            [
                    "<string-length><topic-name><UNSUBSCRIBE_PAYLOAD>",
                    "<string-length><topic-name>"
            ],

        "<UNSUBACK>": #HAS NO PAYLOAD
            [r'\xb<reserved-0>\x02<UNSUBACK_VARIABLE_HEADER><UNSUBACK_PROPERTY>\x<UNSUBACK_PAYLOAD>'],

        "<UNSUBACK_VARIABLE_HEADER>":
            ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS UNSUBSCRIBE PACKET

        "<UNSUBACK_PROPERTY>":
            [
                '<property-0>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
            ],

        "<UNSUBACK_PAYLOAD>":
            [
                "00", #SUCCESS - MAXIMUM QOS0
                "11", #NO SUBSCRIPTION EXISTED
                "80", #UNSPECIFIED ERROR
                "83", #IMPLEMENTATION SPECIFIC ERROR
                "87", #NOT AUTHORIZED
                "8F", #TOPIC FILTER INVALID
                "91", #PACKET IDENTIFIER IN USE
            ],


        "<PINGREQ>": 
        #PINGREQ DOES NOT HAVE VARIABLE HEADER NOR PAYLOAD. 
        #FIXED HEADER: 
        #1. MQTT CONTROL PACKET TYPE (12)
        #2. RESERVED (NOT SPECIFIED)
        #3. REMAINING LENGTH (0)
        [r'\xc<reserved-0>\00'],

        "<PINGRESP>": 
        #PINGRESP DOES NOT HAVE VARIABLE HEADER NOR PAYLOAD. 
        #FIXED HEADER: 
        #1. MQTT CONTROL PACKET TYPE (13)
        #2. RESERVED (NOT SPECIFIED)
        #3. REMAINING LENGTH (0)
        [r'\xd<reserved-0>\00'],

        "<DISCONNECT>":
        #DISCONNECT DOES NOT HAVE PAYLOAD. 
        #FIXED HEADER: 
        #1. MQTT CONTROL PACKET TYPE (14)
        #2. RESERVED (0)
        #3. REMAINING LENGTH (0)
        [
                r'\xe0\00',
                r'\xe0<remaining-length><DISCONNECT_VARIABLE_HEADER><DISCONNECT_PROPERTY>',
        ],

        "<DISCONNECT_VARIABLE_HEADER>":
            [
                    r'\x<disconnect-reason-code>',
            ],

        "<disconnect-reason-code>":
            [
                "00", #NORMAL DISCONNECTION
                "04", #DISCONNECT WITH WILL MESSAGE
                "80", #UNSPECIFIED ERROR
                "81", #MALFORMED PACKET
                "82", #PROTOCOL ERROR
                "83", #IMPLEMENTATION SPECIFIC ERROR
                "87", #NOT AUTHORIZED
                "89", #SERVER BUSY
                "8B", #SERVER SHUTTING DOWN
                "8D", #KEEP ALIVE TIMEOUT
                "8E", #SESSION TAKEN OVER
                "8F", #TOPIC FILTER INVALID
                "90", #TOPIC NAME INVALID
                "93", #RECEIVE MAXIMUM EXCEEDED
                "94", #TOPIC ALIAS INVALID
                "95", #PACKET TOO LARGE
                "96", #MESSAGE RATE TOO HIGH
                "97", #QUOTA EXCEEDED
                "98", #ADMINISTRATIVE ACTION
                "99", #PAYLOAD FORMAT INVALID
                "9A", #RETAIN NOT SUPPORTED
                "9B", #QOS NOT SUPPORTED
                "9C", #USE ANOTHER SERVER
                "9D", #SERVER MOVED
                "9F", #CONNECTION RATE EXCEEDED
                "A0", #MAXIMUM CONNECT TIME
                "A1", #SUBSCRIPTION IDENTIFIERS NOT SUPPORTED
                "A2", #WILDCARD SUBSCRIPTIONS NOT SUPPORTED
                    
            ],

        "<DISCONNECT_PROPERTY>":
            [
                '<property-0>',
                '<property-session-expiry-interval>',
                '<property-reason-string>', #TODO
                '<property-user-property>', #TODO
                '<property-server-reference>', #TODO
            ],

        "<AUTH>":
            [
                    r'\xf<reserved-0><remaining-length><AUTH_VARIABLE_HEADER><AUTH_PROPERTY>', #AUTH HAS NO PAYLOAD

            ],

        "<AUTH_VARIABLE_HEADER>":
            [
                    r'\x<auth-reason-code>',
            ],

        "<auth-reason-code>":
            [
                    "00", #SUCCESS
                    "18", #CONTINUE AUTHENTICATION
                    "19", #RE-AUTHENTICATE

            ],

        "<AUTH_PROPERTY>":
            [
                    "<property-0>",
                    "<property-authentication-method>",
                    "<property-authentication-data>",
                    "<property-reason-string>",
                    "<property-user-property>", #TODO
            ],



                        
        #"<packet-type>":
        #    ["<hexdigit>"],


    "<hexdigit>":
        [
            "0", 
            "1",
            "2",
            "3", 
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f"
        ], 

        "<digit>":
            [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        
        "<reserved-0>":
        ["0"], 
        
        "<reserved-2>":
        ["2"], 
        
        "<protocol-name-length>":
            [r'\x00\x04'],#4

        "<protocol-name>":
            [r'\x4d\x51\x54\x54'],#MQTT

        "<protocol-version>":
            [
                    #r'\x03', #Version 3.1
                    #r'\x04', #Version 3.1.1
                    r'\x05' #Version 5
            ],



        "<connect-flags>":
            ["00", 
                    "02", #RESERVED DISABLED CLEANSESS ENABLED
                    "04", # WILL FLAG ENABLED EVERYTHING ELSE DISABLED
                    "06", # WILL FLAG ENABLED CLEANSESS ENABLED
                    "08", # WILLQOSflag = At Least once delivery ENABLED 
                    "0a", #WILLQOSFLAG = AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
                    "0c", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED 
                    "0e", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "10", #WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    "12", #WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    "14", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "16", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "20", #WILLRETAINFLAG= ENABLED 
                    "22", #WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
                    "24", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
                    "26", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "28", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
                    "2a", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
                    "2c", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED
                    "2f", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "30", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    "32", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYCLEANSESS ENABLED
                    "34", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED
                    "36", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED CLEANSESS ENABLED
                    "80", #USERNAME ENABLED
                    "82", #USERNAME ENABLED CLEANSESS ENABLED
                    "84", #USERNAME ENABLED WILL FLAG ENABLED
                    "86", #USERNAME ENABLED WILL FLAG ENABLED CLEANSES ENNABLED
                    "88", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED
                    "8a", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED CLEANSESS ENABLED
                    "8c", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED
                    "8e", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "90", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
                    "92", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    "94", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "96", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "a0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED
                    "a2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
                    "a4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
                    "a6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "a8", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
                    "aa", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    "ac", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED
                    "ae", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "b0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
                    "b2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    "b4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "b6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "c0", #USERNAME ENABLED PASSWORD ENABLED
                    "c2", #USERNAME ENABLED PASSWORD ENABLED CLEANSESS ENABLED
                    "c4", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED
                    "c6", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "c8", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
                    "ca", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    "cc", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
                    "ce", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG=ENABLED CLEANSESS ENABLED
                    "d0", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    "d2", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    "d4", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "d6", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "e0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED
                    "e2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDCLEANSESS ENABLED
                    "e4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED
                    "e6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "e8", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
                    "ea", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    "ec", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
                    "ee", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED CLEANSESS ENABLED
                    "f0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    "f2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    "f4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVER WILL FLAG ENABLED
                    "f6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED

                ],

            "<connect-flags-defaultpayload>":
                #IF the will flag is set to 0, the will QoS and will retain fields in the connect flags must be set to zero.
                [
                    "00",
                    "02", #RESERVED DISABLED CLEANSESS ENABLED
                    #"08", # WILLQOSflag = At Least once delivery ENABLED 
                    #"0a", #WILLQOSFLAG = AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
                    #"10", #WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    #"12", #WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    #"20", #WILLRETAINFLAG= ENABLED 
                    #"22", #WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
                    #"28", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
                    #"2a", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
                    #"30", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    #"32", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                ],

            "<connect-flags-willflag>": 
                #IF the will flag is set to 1, the will QoS and will retain fields in the connect flags will be used by the server.
                [
                    "04", # WILL FLAG ENABLED EVERYTHING ELSE DISABLED
                    "06", # WILL FLAG ENABLED CLEANSESS ENABLED
                    "0c", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED 
                    "0e", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "14", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "16", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "24", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
                    "26", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "2c", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED
                    "2f", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "34", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED
                    "36", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED CLEANSESS ENABLED
                ], 

               
            
            "<connect-flags-usernameflag>":
                #if WILLFLAG==0, THEN WILLQOS=0
                #IF WILLFLAG==1, THEN WILLQOS=0, 1, OR 2
                #IF WILLFLAG==0, THEN WILLRETAIN=0
                #IF WILLFLAG==1, THEN WILLRETAIN=0, OR 1
                [

                    "80", #USERNAME ENABLED
                    "82", #USERNAME ENABLED CLEANSESS ENABLED
                    #"88", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED
                    #"8a", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED CLEANSESS ENABLED
                    #"90", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
                    #"92", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    #"a0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED
                    #"a2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
                    #"a8", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
                    #"aa", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    #"b0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
                    #"b2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                ],
            
            "<connect-flags-usernameflag-willflag>":
                [

                    "84", #USERNAME ENABLED WILL FLAG ENABLED
                    "86", #USERNAME ENABLED WILL FLAG ENABLED CLEANSES ENNABLED
                    "8c", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED
                    "8e", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "94", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "96", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "a4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
                    "a6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "ac", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED
                    "ae", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "b4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "b6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                ],
             
            "<connect-flags-passwordflag>":
                #if WILLFLAG==0, THEN WILLQOS=0
                #IF WILLFLAG==1, THEN WILLQOS=0, 1, OR 2
                #IF WILLFLAG==0, THEN WILLRETAIN=0
                #IF WILLFLAG==1, THEN WILLRETAIN=0, OR 1
                [

                    "c0", #USERNAME ENABLED PASSWORD ENABLED
                    "c2", #USERNAME ENABLED PASSWORD ENABLED CLEANSESS ENABLED
                    #"c8", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
                    #"ca", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    #"d0", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    #"d2", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                    #"e0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED
                    #"e2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDCLEANSESS ENABLED
                    #"e8", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
                    #"ea", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
                    #"f0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
                    #"f2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
                ],
            
            "<connect-flags-usernameflag-passwordflag-willflag>":
                [

                    "c4", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED
                    "c6", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "cc", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
                    "ce", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG=ENABLED CLEANSESS ENABLED
                    "d4", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
                    "d6", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                    "e4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED
                    "e6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
                    "ec", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
                    "ee", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED CLEANSESS ENABLED
                    "f4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVER WILL FLAG ENABLED
                    "f6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
                ],


            "<keep-alive>":
                [r'\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'],


            "<property-length>":
                [
                        r'\x03'
                        #r'\n\n'
                ],

            "<connect-property>":
                [
                        r'\x21', #Receive Maximum
                        #r'\x11', #Session Expiry Interval
                        #r'\x15', #Authentication Method
                        #r'\x16', #Authentication Data
                        #r'\x17', #Request Problem Information
                        #r'\x19', #Request Response Information
                        #r'\x22', #Topic Alias Maximum
                        #r'\x26', #User Property
                        #r'\x27', #Maximum Packet Size
                ],

            "<property-value>":
                [
                        #r'\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>',
                        r'\x00\x14',
                ],

            #"<will-property>":
            #    [
            #            #r'\x00'#TODO ADD ALL PROPERTIES
            #            r'\v'
            #    ], 

            "<client-id>":#1-23 CHARACTERS, BUT SPECIFICATIONS STATES THAT IT COULD BE MORE.
                [
                        #r'\x<encoded-strings><client-id>', 
                        #r'\x<encoded-strings>'
                        "<utf8-numbers><client-id>",
                        "<utf8-numbers>",
                        "<utf8-latin-capitalletters><client-id>",
                        "<utf8-latin-capitalletters>",
                        "<utf8-latin-smallletters><client-id>",
                        "<utf8-latin-smallletters>"

                ], 

                "<will-topic>":
                    [
                            #r'\x<hexdigit><hexdigit><will-topic>', 
                            #r'\x<hexdigit><hexdigit>'
                            "<utf8-characters><will-topic>",
                            "<utf8-characters>"
                    ],

                "<will-message>":
                    [
                            #r'\x<hexdigit><hexdigit><will-message>', 
                            #r'\x<hexdigit><hexdigit>'
                            "<utf8-characters><will-message>",
                            "<utf8-characters>"
                    ],

                "<username>":
                    [
                            #r'\x<hexdigit><hexdigit><username>', 
                            #r'\x<hexdigit><hexdigit>'
                            "<utf8-characters><username>",
                            "<utf8-characters>"
                    ],

                "<password>":
                    [
                            #r'\x<hexdigit><hexdigit><password>', 
                            #r'\x<hexdigit><hexdigit>'
                            "<utf8-characters><password>",
                            "<utf8-characters>"
                    ],

                "<publish-reserved-qos0>":
                [
                    "1", #DUP:0 QOS:0 RETAIN:0
                    #"8", #DUP:1 QOS:0 RETAIN:0 #THE DUP FLAG MUST BE SET TO 0 FOR ALL QOS MESSAGES
                    #"9"  #DUP:1 QOS:0 RETAIN:1 #THE DUP FLAG MUST BE SET TO 0 FOR ALL QOS MESSAGES
                ],

            "<publish-reserved-qos12>":
                [
                    "2", #DUP:0 QOS:1 RETAIN:0
                    "3", #DUP:0 QOS:1 RETAIN:1
                    "a", #DUP:1 QOS:1 RETAIN:0
                    "b", #DUP:1 QOS:1 RETAIN:1
                    "4", #DUP:0 QOS:2 RETAIN:0
                    "5", #DUP:0 QOS:2 RETAIN:1
                    "c", #DUP:1 QOS:2 RETAIN:0
                    "d"  #DUP:1 QOS:2 RETAIN:1
                ],


            "<subscribe-reserved-qos>":
                [r'\x00', r'\x01', r'\x02'],

            "<topic-name>":
                [
                        #r'\x<hexdigit><hexdigit><topic-name>', 
                        #r'\x<hexdigit><hexdigit>', 
                        "<utf8-characters><topic-name>",
                        "<utf8-characters>",
                        r'<topic-name>\x2f<topic-name>'
                ],

            "<message>":
                [
                        #r'\x<hexdigit><hexdigit><message>', 
                        #r'\x<hexdigit><hexdigit>'
                        "<utf8-characters><message>",
                        "<utf8-characters>"
                ],


            "<packet-identifier>":
                [r'\x<digit><digit>\x<digit><digit>'],

            "<utf8-characters>":
                [
                        "<utf8-numbers>", 
                        "<utf8-latin-capitalletters>", 
                        "<utf8-latin-smallletters>", 
                        #"<utf8-symbols>"
                ],

            #"<encoded-strings>":
            #    [
            #            #"30", # 0 DO 0 LATER.
            #            "31", # 1
            #            "32", # 2
            #            "33", # 3
            #            "34", # 4
            #            "35", # 5
            #            "36", # 6
            #            "37", # 7
            #            "38", # 8
            #            "39", # 9
            #            "41", # A
            #            "42", # B
            #            "43", # C
            #            "44", # D
            #            "45", # E
            #            "46", # F
            #            "47", # G
            #            "48", # H
            #            "49", # I
            #            "4a", # J
            #            "4b", # K
            #            "4c", # L
            #            "4d", # M
            #            "4e", # N
            #            "4f", # O
            #            "50", # P
            #            "51", # Q
            #            "52", # R
            #            "53", # S
            #            "54", # T
            #            "55", # U
            #            "56", # V
            #            "57", # W
            #            "58", # X
            #            "59", # Y
            #            "5a", # Z
            #            "61", # a
            #            "62", # b
            #            "63", # c
            #            "64", # d
            #            "65", # e
            #            "66", # f
            #            "67", # g
            #            "68", # h
            #            "69", # i
            #            "6a", # j
            #            "6b", # k
            #            "6c", # l
            #            "6d", # m
            #            "6e", # n
            #            "6f", # o
            #            "70", # p
            #            "71", # q
            #            "72", # r
            #            "73", # s
            #            "74", # t
            #            "75", # u
            #            "76", # v
            #            "77", # w
            #            "78", # x
            #            "79", # y
            #            "7a", # z
            #
            #    ],
                
                "<utf8-numbers>":
                    [r'\x30', r'\x31', r'\x32', r'\x33', r'\x34', r'\x35', r'\x36', r'\x37', r'\x38', r'\x39'],

                "<utf8-latin-capitalletters>":
                    [r'\x41', r'\x42', r'\x43', r'\x44', r'\x45', r'\x46', r'\x47', r'\x48', r'\x49', r'\x4a', r'\x4b', r'\x4c', r'\x4d', r'\x4e', r'\x4f', r'\x50', r'\x51', r'\x52', r'\x53', r'\x54', r'\x55', r'\x56', r'\x57', r'\x58', r'\x59', r'\x5a'],
                    "<utf8-latin-smallletters>":
                    [r'\x61', r'\x62', r'\x63', r'\x64', r'\x65', r'\x66', r'\x67', r'\x68', r'\x69', r'\x6a', r'\x6b', r'\x6c', r'\x6d', r'\x6e', r'\x6f', r'\x70', r'\x71', r'\x72', r'\x73', r'\x74', r'\x75', r'\x76', r'\x77', r'\x78', r'\x79', r'\x7a'],

            "<utf8-symbols>":
                [r'\x20', r'\x21', r'\x22', r'\x23', r'\x24', r'\x25', r'\x26', r'\x27', r'\x28', r'\x29', r'\x2a', r'\x2b', r'\x2c', r'\x2d', r'\x2e', r'\x2f', r'\x3a', r'\x3b', r'\x3c', r'\x3d', r'\x3e', r'\x3f', r'\x40', r'\x5b', r'\x5c', r'\x5d', r'\x5e', r'\x5f', r'\x60', r'\x7b', r'\x7c', r'\x7d', r'\x7e', r'\xc2\xa0', r'\xc2\xa1', r'\xc2\xa2', r'\xc2\xa3', r'\xc2\xa4', r'\xc2\xa5', r'\xc2\xa6', r'\xc2\xa7', r'\xc2\xa8', r'\xc2\xa9', r'\xc2\xaa', r'\xc2\xab', r'\xc2\xac', r'\xc2\xad', r'\xc2\xae', r'\xc2\xaf', r'\xc2\xb0', r'\xc2\xb1', r'\xc2\xb2', r'\xc2\xb3', r'\xc2\xb4', r'\xc2\xb5', r'\xc2\xb6', r'\xc2\xb7', r'\xc2\xb8', r'\xc2\xb9', r'\xc2\xba', r'\xc2\xbb', r'\xc2\xbc', r'\xc2\xbd', r'\xc2\xbe', r'\xc2\xbf'
                ],

            "<utf8-letters-accents>":
                [r''],

            "<remaining-length>":
                [r'\t'], 

            "<string-length>":
                [r'\n\n'],

        }
