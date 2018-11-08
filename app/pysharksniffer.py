import sys
import pyshark
import threading
from io import StringIO
import time
from datetime import datetime
from random import random
from flask_socketio import SocketIO, emit
from models import Template
import shlex

SAVE_FOLDER_PATH = 'static/tracefiles/'
class PysharkSniffer(threading.Thread): # This class starts the PyShark master sniffer that updates a list of communicating APs and a list of established communications
    #def __init__(self, db, interface_string, lock, bpf_filter=None, display_filter=None, socketio=None, intervals=True, timeout=10, sleep=10):
    def __init__(self, db, temp_id, socketio):
        threading.Thread.__init__(self)
        # self.interface = interface_string
        # self.lock = lock
        # self.cap = None
        self._stopper = threading.Event()
        # self.intervals = intervals
        # self.timeout = timeout
        # self.sleep = sleep
        self.on = False
        self.socketio = socketio
        # self.bpf_filter = bpf_filter
        # self.display_filter = display_filter
        self.output_file = None
        self.db = db
        self.temp_id = temp_id
        self.template = None

    def stop(self):
        self._stopper.set()
        return [self.filename, self.temp_id]

    def stopped(self):
        return self._stopper.isSet()

    def getTemplate(self):
        return self.template

    def run(self):
        self.start_time = datetime.now()
        self.frame_no = 0
        #self.filename = datetime.strftime(datetime.now(), '%Y%m%d%s')  + '.pcap'


        self.template = Template.query.filter_by(id=self.temp_id).one()
        extra_params = shlex.split(self.template.command)

        isNext = False
        self.filename = None

        params = []
        for param in extra_params:
            if isNext:
                self.filename = param
                isNext = False
                continue

            if param == '-w':
                isNext = True
                continue

            params += [param]

        param_str = ' '.join(params)

        if self.filename is not None:
            self.output_file = SAVE_FOLDER_PATH + self.filename

        capture = pyshark.LiveCapture(extra_params_str=param_str, output_file=self.output_file)
        capture.set_debug()

        isFirst = True
        for p, pid in capture.sniff_continuously():
            if isFirst:
                try:

                    self.template.process_id = pid
                    self.db.session.commit()
                except Exception as e:
                    print(e)

            self.perPacket(p, pid)
            isFirst = False

        print('stopped')
        self.template = None
        self.socketio.emit('errordata', {'data': {'temp_id':self.temp_id, "message":[{'type':'warning', 'message':'Incorrect tshark parameters.'}]}}, namespace='/stopcapture')
        sys.exit()

    def getDetail(self, packet):
        detail = ''

        for line in packet.__str__().split('\n'):
            if line == 'self._packet_string':
                continue
            elif 'Layer ETH' in line:
                detail += '''<div class="panel panel-default">
                              <div class="panel-heading" role="tab">
                                <h4 class="panel-title">
                                  <a class="packetHeader" data-target="#%(link)s">
                                    <i class="fa fa-caret-right fa-rotate-90"></i>
                                    %(name)s
                                  </a>
                                </h4>
                              </div>
                              <div id="%(link)s" class="panel-collapse">
                                <div class="panel-body">

                ''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
            elif 'Layer' in line:
                detail += '''</div>
                              </div>
                            </div>
                            <div class="panel panel-default">
                              <div class="panel-heading" role="tab">
                                <h4 class="panel-title">
                                  <a class="packetHeader" data-target="#%(link)s">
                                    <i class="fa fa-caret-right"></i>
                                    %(name)s
                                  </a>
                                </h4>
                              </div>
                              <div id="%(link)s" class="panel-collapse collapse">
                                <div class="panel-body">

                ''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
            else:
                keyword = line.split(': ')[0] + ': '

                try:
                    value = line.split(': ')[1]
                except IndexError:
                    keyword = ''
                    value = line

                try:
                    keyword = keyword.split('= ')[1]
                except IndexError:
                    pass

                detail += '<p><strong>%s</strong> %s</p>\n' % (keyword, value)

        detail += '</div></div></div>'

        return detail
    def get_ip_version(self, packet):
        for layer in packet.layers:
            if layer._layer_name == 'ip':
                return 4
            elif layer._layer_name == 'ipv6':
                return 6

    def perPacket(self, packet, pid):
        data = {}

        print('received new packet')

        time = (datetime.now() - self.start_time).total_seconds()
        pkt_length = packet.captured_length
        self.frame_no = self.frame_no + 1

        protocol = packet.transport_layer
        detail = self.getDetail(packet)
        ip_version = self.get_ip_version(packet)
        highest_layer = packet.highest_layer
        if ip_version == 4:
            ip = packet.ip

        elif ip_version == 6:
            ip = packet.ipv6

        if protocol == 'TCP':
            src_ip = ip.src
            dst_ip = ip.dst
            protocol = 'TCP'
        elif protocol == 'UDP':
            try:
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = packet.transport_layer
            except Exception as e:
                print(e)
        else:
            if highest_layer != 'ARP':
                print(highest_layer)
                try:
                    src_ip = ip.src
                except Exception as e:
                    src_ip = ''

                try:
                    dst_ip = ip.dst
                except Exception as e:
                    dst_ip = ''

                protocol = highest_layer
            else:
                src_ip = ''
                dst_ip = 'Broadcast'
                protocol = highest_layer

        data['time'] = time
        data['no'] = self.frame_no
        try:
            data['src_ip'] = src_ip
            data['dst_ip'] = dst_ip
        except Exception as e:
            print(e)
        data['protocol'] = protocol
        data['length'] = pkt_length
        data['detail'] = detail
        data['info'] = ''
        data['pid'] = pid
        data['temp_id'] = self.temp_id

        if self.stopped():
            self.socketio.emit('errordata', {'data': {'temp_id':self.temp_id, "message":[{'type':'success', 'message':self.template.name + " was stopped now."}]}}, namespace='/stopcapture')
            print('stopped')
            self.template = None
            sys.exit()
        else:
            if self.template is not None:
                self.socketio.emit('newdata', {'data': data}, namespace='/livecapture')
            pass

if __name__ == "__main__":
    lock = threading.Lock()
    #while True:
    sniffer = PysharkSniffer("eth0", lock, False)
    print("Main sniffer started")
    sniffer.start()
    #x = raw_input("sdadsa")
    #sniffer.stop()
    #sniffer.join()
    #print("Main sniffer stopped")
    #x = raw_input("sdasda")
