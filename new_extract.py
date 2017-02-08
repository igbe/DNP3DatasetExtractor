import pyshark
import binascii
import decimal

"""
FOR ONLY IPV4
features to be extracted
service
flag
src_bytes
dst_bytes
logged_in
count
serror_rate
srv_serror_rate
same_srv_rate
diff_srv_rate
dist_host_srv_count
dist_host_same_srv_rate
dist_host_diff_srv_rate
dist_host_serror_rate
dist_host_srv_serror_rate

Non-dnp3 communication on a dnp3 port? (Boolean)
Checksum Correct or not? (Boolean)
Dnp3 Datalink Payload length == actual payload length(Boolean)
function not implemented message count?
RTT for each packet req/resp Check from sending a function till the time it is received.
In dreaded Function code? (Boolean)
"""


"""
What constitutes a Connection Record:
1. The start time of the connection.
2. The end time of the connection.
3. Originating host. The host that initiated the connection.
4. Originating port. The port on host that initiated the connection.
5. Responding host. The host that responded to the connection.
6. Service also called protocol. The port on the host that responded to the connection.
7. state that the connection ended in. This can be one of the following:

    SF normal SYN/FIN completion
    REJ connection rejected - initial SYN elicited a RST in reply
    S0 state 0: initial SYN seen but no reply
    S1 state 1: connection established (SYN's exchanged), nothing further seen
    S2 state 2: connection established, initiator has closed their side
    S3 state 3: connection established, responder has closed their side

    S4 state 4: SYN ack seen, but no initial SYN seen ------------------>> not implemented delete any connection that's not a member of a connection

    RSTOSn connection reset by the originator when it was in state n
    RSTRSn connection reset by the responder when it was in state n
    SS SYN seen for already partially-closed connection
    SH a state 0 connection was closed before we ever saw the SYN ack

    SHR a state 4 connection was closed before we ever saw the original SYN ------------------>> not implemented delete any connection that's not a member of a connection
    OOS1 SYN ack did not match initial SYN ------------------>> not implemented delete any connection that's not a member of a connection
    OOS2 initial SYN retransmitted with different sequence number ------------------>> not implemented delete any connection that's not a member of a connection

   Note that connections ending in states S2 and S3 (or terminated by RST's after being in this state; e.g., RSTO3) may have
   byte counts associated with them. These connections were "half-closed". If the side that was half-closed was closed by a
   FIN packet, then the FIN packet provides an accurate byte count for the side that was closed, and a lower-bound byte count
   for the other side (from the sequence number ack'd by the FIN). Thus you may trust one of the byte counts, and the other is
   probably equal to or just a bit below the final byte count, though it could be much below if the connection persisted
   half-open for a long time.
8. All the captured packets in the connection

 """


class Dataset():
    def __init__(self,timestamp_precision='second',time_based_feat_intv_sec=1):
        self.conn_id = []
        self.record = {}
        self.timestamp_precision = timestamp_precision
        self.time_based_feat_intv_sec = time_based_feat_intv_sec #in milliseconds

        self.precision = {'second':1,'millisecond':1000,'microsecond':1000000, 'nanosecond':1000000000}
        self.proto = {'1':'icmp','6':'tcp','17':'udp'}

        #pass

    def isnewconnection(self,pkt):
        """
        function for finding out if a pkt is the start of a new connection
        :param pkt: test packet
        :return: true or false
        """
        if (pkt.tcp.flags_syn == '1') and (pkt.tcp.flags_ack == '0'):

            #To capture the exception where the connection request is resent i.e. retransmitted, we use the loop
            #this will ensure that the connections are unique. you can choose to use the retransmissions later.
            for conn in self.conn_id:
                if self.record[conn][0][1:-1]==[pkt.ip.src,pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport]:
                    print "Retransmitted new connection SYN packet seen --Note this is not added as a new conenction since it's part of an already existing connection"
                    return False

            return True
        else:
            return False

    def addnewconnection(self,pkt,count):
        """
        function for adding a new connection and its name to a connection list when new one if found
        :param pkt: the test packet
        :param count: the packet number in wireshark
        :return: nothing
        """
        #print pkt.layers ,"\n"
        #print pkt.sniff_timestamp
        #print pkt.ip.src
        #print pkt[pkt.transport_layer].srcport
        #print pkt.ip.dst
        #print pkt[pkt.transport_layer].dstport, '\n'

        # Record Structure:
        # self.record = {'connection_id':[[timestamp,ip.src,srcport, ip.dst,dstport,state],[]]}
        # Note state can be SF,REJ,S0,S1,S2,S3,RSTOSn,RSTRSn,SS or SH. Here, your code should kep updating the state of
        # a connection depending on the packet it sees until the final possible state

        self.record["{0}".format(count)] = [[pkt.sniff_timestamp, pkt.ip.src,
                                                    pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport,''], []]
        self.conn_id.append("{0}".format(count))
        #self.conn_no += 1

    def part_of_existing_connection(self,pkt):
        """
        function for adding a pkt to an already existing connection. i.e if a packet is part of an ungoing connection,
        this packet will be appended to that connection
        :param pkt: test packet
        :return:  True/False, connection name
        """
        #print "self.record.keys()",self.record.keys()
        for connection_id in self.record.keys():
            value = self.record[connection_id][0]
            #print "connection_id",connection_id,"value", value
            #print pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport
            option1 = [pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport]
            option2 =[pkt.ip.dst, pkt[pkt.transport_layer].dstport, pkt.ip.src, pkt[pkt.transport_layer].srcport]
            #print option1, option2
            #print option2
            if (option1 == value[1:-1]) or (option2 == value[1:-1]):
                #print "yes part of an existing connection"
                return True, connection_id
            #mind you an attempt to place an else here with return False, None causes some connections to be lost
    def rmv_conn_with_only_1pkt(self):
        print "deleting connections with only one packet i.e incomplete trace connection due to abrupt wireshark or tcpdump termination"
        print "for future use of this and say attach it to state S0"
        count = 0
        deleted_conns= []
        for connection_id in self.record.keys():
            if len(self.record[connection_id][1])==1:
                #print self.record[connection_id]
                deleted_conns.append(connection_id)
                del self.record[connection_id]
                self.conn_id.remove(connection_id)
                count +=1
        print count, "connections deleted", "who's connection ID's are: ", deleted_conns
        print len(self.conn_id), "connections remaining"

    def create_record(self,allpackets):
        """
        What constitutes a Connection Record:
        1. The start time of the connection.
        2. The end time of the connection. ---> I will skip this and just put the start time of a connection as mistakes in
            pcap captures might mean that there might not be any fin or rst which are flags used to identify end of a conn.
        3. Originating host. The host that initiated the connection.
        4. Originating port. The port on host that initiated the connection.
        5. Responding host. The host that responded to the connection.
        6. Service. The port on the host that responded to the connection.
        7. All the captured packets in the connection

        :param allpackets: all the data packets captured
        :return:
        """
        #Record Structure:
        #self.record = {'connection_id':[[timestamp,ip.src,srcport, ip.dst,dstport,state],[]]}
        #Note state can be SF,REJ,S0,S1,S2,S3,RSTOSn,RSTRSn,SS or SH. Here, your code should kep updating the state of
        # a connection depending on the packet it sees until the final possible state



        count = 1
        for pkt in allpackets:

            #print "timestamp",pkt.sniff_timestamp
            try:
                pkt.ip.version
            except:
                print "contains IPV6 packets, and this application doesn't support it"
                exit()
            print 'count', count

            if (pkt.transport_layer == "TCP"):
                # print pkt.tcp.flags_syn,type(pkt.tcp.flags_syn),pkt.tcp.flags_ack,type(pkt.tcp.flags_ack)
                if self.isnewconnection(pkt):
                    self.addnewconnection(pkt,count)
                    # add this pkt to record
                    # continue
                answer, conn = self.part_of_existing_connection(pkt)
                #print "part_of_existing_connection", answer,conn
                if conn == None:
                    count += 1
                    continue
                if answer == True:
                    #print count," appended to ", conn, "\n"
                    self.record[conn][1].append(pkt)
            count +=1
        #to remove wrongly terminated connections from the dataset
        self.rmv_conn_with_only_1pkt()
        print self.record, "\n"
        #print self.conn_id


def create_dataset(allpackets):

    dataset = Dataset(timestamp_precision='second',time_based_feat_intv_sec=2) #
    dataset.create_record(allpackets)
    #dataset.get_features()
    #dataset.get_time_based_feat()




if __name__ == "__main__":
    cap = pyshark.FileCapture("test.pcap") #normal_mst.pcap #normal_slv.pcap #dos_sa_master1 #test.pcap
    create_dataset(cap)
    #time = pkt.sniff_timestamp

