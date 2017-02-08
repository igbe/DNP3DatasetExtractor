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
6. Service. The port on the host that responded to the connection.
7. All the captured packets in the connection

"""
class Dataset():
    def __init__(self,timestamp_precision='second',time_based_feat_intv_sec=1):
        self.conn_id = []
        self.record = {}
        self.timestamp_precision = timestamp_precision
        self.time_based_feat_intv_sec = time_based_feat_intv_sec #in milliseconds

        self.precision = {'second':1,'millisecond':1000,'microsecond':1000000, 'nanosecond':1000000000}
        self.proto = {'1':'icmp','6':'tcp','17':'udp'}

    def isnewconnection(self,pkt):
        """
        function for finding out if a pkt is the start of a new connection
        :param pkt: test packet
        :return: true or false
        """
        if (pkt.tcp.flags_syn == '1') and (pkt.tcp.flags_ack == '0'):

            #To capture the exception where the connection request is resent i.e. retransmitted, we use the loop
            #this will ensure that the connections are unique. you can choose to use the retransmissions later.
            for conn in self.record.keys():
                if self.record[conn][0][1:]==[pkt.ip.src,pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport]:
                    return False

            return True
        else:
            return False
    def isendofconnection(self,pkt):
        if (pkt.tcp.flags_fin == '1') or (pkt.tcp.flags_res == '0'):
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

        self.record["{0}".format(count)] = [[pkt.sniff_timestamp, pkt.ip.src,
                                                    pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport], []]
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
            #print option1
            #print option2
            if (option1 == value[1:]) or (option2 == value[1:]):

                #print "found keys"
                return True , connection_id
    def rmv_conn_with_only_1pkt(self):
        print "deleting connections with only one packet i.e incomplete trace connection dues to abrupt wireshark or tcpdump termination"
        for connection_id in self.record.keys():
            if len(self.record[connection_id][1])==1:
                del self.record[connection_id]
                self.conn_id.remove(connection_id)



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
                if answer == True:
                    #print count," appended to ", conn, "\n"
                    self.record[conn][1].append(pkt)
            count +=1
        #to remove wrongly terminated connections from the dataset
        self.rmv_conn_with_only_1pkt()
        print self.record, "\n"
        #print self.conn_id

    def get_duration(self,connection_id):

        try:
            duration = abs(float(self.record[connection_id][1][0].sniff_timestamp) - float(self.record[connection_id][1][-1].sniff_timestamp))
            return duration*self.precision[self.timestamp_precision]
        except IndexError:
            print "Warning: An incomplete connection found in your data-->could be because of a DoS or connection timeout"
            return 0.0

    def get_protocol(self,connection_id):
        """
        This feature indicates the type of transport protocol used in the connection, e.g. TCP,UDP
        :param connection_id:
        :return:
        """
        #print "in get Protocol"
        #print self.record[connection_id]
        return self.proto[self.record[connection_id][1][0].ip.proto]

    def get_service(self,connection_id):
        return self.record[connection_id][0][-1]

    def get_src_bytes(self,connection_id):
        count = 0
        for pkt in self.record[connection_id][1]:
            if pkt.ip.src == self.record[connection_id][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count

    def get_dst_bytes(self,connection_id):
        count = 0
        for pkt in self.record[connection_id][1]:
            if pkt.ip.dst == self.record[connection_id][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count

    def get_flag(self,connection_id):
        count = 0
        for pkt in reversed(self.record[connection_id][1]):
            if count >2:
                return "none"
            if pkt.tcp.flags_fin == '1':
                return "fin"
            if pkt.tcp.flags_reset =='1':
                return "rst"
            count +=1

    def get_urgent_count(self,connection_id):
        count=0
        for pkt in self.record[connection_id][1]:
            if pkt.tcp.flags_urg == '1':
                count = count + 1
        #print count
        return count
    def get_land(self,connection_id):
        #print self.record[connection_id][0][1], self.record[connection_id][0][3]
        if self.record[connection_id][0][1] == self.record[connection_id][0][3]:
            return 1
        else:
            return 0

    def get_time_based_feat(self):
        #for time based calculation Decima library presicion
        #decimal.getcontext().prec = 6
        self.conn_interval_elem = {}
        i=0
        for conn in self.conn_id:
            end = decimal.Decimal('%s'%(self.record[conn][0][0]))
            start = end - decimal.Decimal(self.time_based_feat_intv_sec)

            prev_conn = []
            for con in reversed(self.conn_id[:i]):
                if decimal.Decimal(self.record[con][0][0]) >= start:
                    #print con
                    prev_conn.append(con)
                    #print "conn time", self.record[con][0][0], 'start', start
                else:
                    continue
            self.conn_interval_elem[conn] = prev_conn

            i+=1
        #print self.conn_interval_elem


    def get_count(self,connection_id):
        """
        The number of connections to the same host as the current connection in the past two seconds(
        replaced by self.time_based_feat_intv_sec)
        :param connection_id: the id of the connection
        :return: count
        """
        # FOR DNP3 (using only one master and slave), THIS FEATURE IS USELESS SINCE YOU ARE ALWAYS CONNECTING TO
        # SAME HOST ALWAYS"

        self.sam_host_count =0
        self.serror_count = 0

        self.rerror_count = 0

        for con in self.conn_interval_elem[connection_id]:
            if self.record[con][0][3] == self.record[connection_id][0][3]:
                    # Note for a SYN ERROR, the syn packet is sent for connection establishment, but the receiver does
                    # not respond with SNY/ACK hence the below line
                if (self.record[connection_id][1][1].tcp.flags_syn and self.record[connection_id][1][1].tcp.flags_ack != '1'):
                    self.serror_count += 1

                #You identify the REJ error by looking at the 1st packet and the second. If the 1st is a syn request,
                #and the second is a reset which means a rejection of the sysn request, then its a REJ error.

                if (self.record[connection_id][1][0].tcp.flags_syn and self.record[connection_id][1][1].tcp.flags_reset == '1'):
                    self.rerror_count += 1


                self.sam_host_count += 1

        return self.sam_host_count

    def get_srv_count(self, connection_id):
        """
        The number of connections to the same service as the current connections in the past two seconds(
        replaced by self.time_based_feat_intv_sec).
        :param connection_id:the id of the connection
        :return: srv_count
        """
        self.same_srv_count = 0
        self.same_host_serror = 0

        self.same_host_rerror = 0

        for con in self.conn_interval_elem[connection_id]:
            #same destination port. Note that self.record[0][4] is the destination port
            if self.record[con][0][4] == self.record[connection_id][0][4]:
                #Same srv rate The rate of connections to the same service in the past two seconds as the current connection.




                    #Note for a SYN ERROR, the syn packet is sent for connection establishment, but the receiver does
                    #not respond with SNY/ACK hence the below line.
                if (self.record[connection_id][1][1].tcp.flags_syn and self.record[connection_id][1][1].tcp.flags_ack != '1'):
                    self.same_host_serror += 1

                #You identify the REJ error by looking at the 1st packet and the second. If the 1st is a syn request,
                #and the second is a reset which means a rejection of the sysn request, then its a REJ error.

                if (self.record[connection_id][1][0].tcp.flags_syn and self.record[connection_id][1][1].tcp.flags_reset == '1'):
                    self.same_host_rerror += 1

                self.same_srv_count += 1
        return self.same_srv_count


    def get_serror_rate(self,connection_id):
        """
        The rate of connections to the same host as the current connection in the past two seconds that have 'SYN' errors.
        SYN error means that you send SYN, but  no
        :param connection_id:
        :return:
        """
        try:
            return float(self.serror_count) / self.sam_host_count
        except:
            return 0.0
    def get_rerror_rate(self,connection_id):
        """
        Same as with 'Serror rate' only with 'REJ' errors instead of 'SYN.'
        :param connection_id:
        :return:
        """
        try:
            pass
            return float(self.rerror_count) / self.sam_host_count
        except:
            return 0.0

    def get_srv_serror_rate(self,connection_id):
        """
        The rate of connections to the same service as the current connections in the past two seconds that have 'SYN' errors.
        :param connection_id:
        :return:
        """
        try:
            return float(self.same_host_serror) / self.same_srv_count
        except:
            return 0.0

    def get_srv_rerror_rate(self,connection_id):
        """
        Same as with 'Srv serror rate' only with 'REJ' errors instead of 'SYN.'
        :param connection_id:
        :return:
        """
        try:
            pass
            return float(self.same_host_rerror) / self.same_srv_count
        except:
            return 0.0






    def get_features(self):

        self.get_time_based_feat()
        for connection_id in self.conn_id:
            #print self.record[connection_id]

            """
            Basic Features
            """
            duration = self.get_duration(connection_id)
            protocol = self.get_protocol(connection_id)
            service = self.get_service(connection_id)
            src_bytes = self.get_src_bytes(connection_id)
            dst_bytes = self.get_dst_bytes(connection_id)
            flag = self.get_flag(connection_id)
            urgent = self.get_urgent_count(connection_id)
            land = self.get_land(connection_id)



            """
            Time based Features
            """
            #self.get_time_based_feat()
            count = self.get_count(connection_id)
            srv_count = self.get_srv_count(connection_id)
            serror_rate = self.get_serror_rate(connection_id)
            srv_serror_rate = self.get_srv_serror_rate(connection_id)
            rerror_rate = self.get_rerror_rate(connection_id)
            srv_rerror_rate = self.get_srv_rerror_rate(connection_id)

            print "duration:", duration, ' proto:', protocol, ' service:', service, \
                ' src_bytes', src_bytes, ' dst_bytes', dst_bytes, ' flag', flag, ' urgent', urgent, ' land', land, \
                ' count', count,' srv_count', srv_count,' serror_rate',serror_rate,' srv_serror_rate',srv_serror_rate, \
                ' rerror_rate', rerror_rate, ' srv_rerror_rate', srv_rerror_rate





            

            




        #pass


def create_dataset(allpackets):

    dataset = Dataset(timestamp_precision='second',time_based_feat_intv_sec=2) #
    dataset.create_record(allpackets)
    dataset.get_features()
    #dataset.get_time_based_feat()




if __name__ == "__main__":
    cap = pyshark.FileCapture("test.pcap") #normal_mst.pcap normal_slv.pcap #dos_sa_master1 #test.pcap
    create_dataset(cap)
    #time = pkt.sniff_timestamp

