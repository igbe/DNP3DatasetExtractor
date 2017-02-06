import pyshark
import binascii

"""
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
    def __init__(self,time_precision):
        #self.conn_no = 0
        self.record = {}
        self.time_precision = time_precision

        self.precision = {'second':1,'millisecond':1000,'microsecond':1000000, 'nanosecond':1000000000}
        self.proto = {'1':'icmp','6':'tcp','17':'udp'}

    def isnewconnection(self,pkt):
        """
        function for finding out if a pkt is the start of a new connection
        :param pkt: test packet
        :return: true or false
        """
        if (pkt.tcp.flags_syn == '1') and (pkt.tcp.flags_ack == '0'):
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
        self.record["{0}".format(count)] = [[pkt.sniff_timestamp, pkt.ip.src,
                                                    pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport], []]
        #self.conn_no += 1

    def part_of_existing_connection(self,pkt):
        """
        function for adding a pkt to an already existing connection. i.e if a packet is part of an ungoing connection,
        this packet will be appended to that connection
        :param pkt: test packet
        :return:  True/False, connection name
        """
        for key in self.record.keys():
            value = self.record[key][0]
            #print "key",key,"value", value
            #print pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport
            option1 = [pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport]
            option2 =[pkt.ip.dst, pkt[pkt.transport_layer].dstport, pkt.ip.src, pkt[pkt.transport_layer].srcport]
            #print option1
            #print option2
            if (option1 == value[1:]) or (option2 == value[1:]):

                #print "found keys"
                return True , key

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
            if pkt.transport_layer == "TCP":
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
        print self.record

    def get_duration(self,key):

        duration = abs(float(self.record[key][1][0].sniff_timestamp) - float(self.record[key][1][-1].sniff_timestamp))
        return duration*self.precision[self.time_precision]

    def get_protocol(self,key):
        return self.proto[self.record[key][1][0].ip.proto]

    def get_service(self,key):
        return self.record[key][0][-1]

    def get_src_bytes(self,key):
        count = 0
        for pkt in self.record[key][1]:
            if pkt.ip.src == self.record[key][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count

    def get_dst_bytes(self,key):
        count = 0
        for pkt in self.record[key][1]:
            if pkt.ip.dst == self.record[key][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count



    def get_basic_features(self):
        for key in self.record.keys():
            #print self.record[key][0]
            duration = self.get_duration(key)
            protocol = self.get_protocol(key)
            service = self.get_service(key)
            src_bytes = self.get_src_bytes(key)
            dst_bytes = self.get_dst_bytes(key)
            print "duration:", duration,' proto:', protocol,' service:', service,\
                ' src_bytes', src_bytes,' dst_bytes', dst_bytes


        #pass


def create_dataset(allpackets):

    dataset = Dataset('second')
    dataset.create_record(allpackets)
    dataset.get_basic_features()




if __name__ == "__main__":
    cap = pyshark.FileCapture("dos_sa_master1.pcap") #normal_mst.pcap normal_slv.pcap #dos_sa_master1
    create_dataset(cap)
    #time = pkt.sniff_timestamp

