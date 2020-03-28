import threading
import pcap
import os
import argparse
import pickle

# https://blog.csdn.net/weixin_39138707/article/details/74612637
# https://blog.csdn.net/u010069213/article/details/17999757
# https://blog.csdn.net/super_yc/article/details/72290931
# https://blog.csdn.net/weixin_34342992/article/details/88004374

"""
程序要求
1. 对TCP、UDP、ARP数据包进行分析
2. 能根据协议类型、地址信息对数据包进行过滤
3. 采用多线程实现
4. 有命令行操作界面，易于使用
5. 单独完成
加分项：
1. 统计了基于ip、mac的流量统计
2. 捕获后过滤
"""
parser = argparse.ArgumentParser()

parser.add_argument("-xieyi", "--xieyi", help="过滤的协议", default="")
parser.add_argument("-mudiip", "--mudiip", help="过滤目的ip地址限制", default="")
parser.add_argument("-yuanip", "--yuanip", help="过滤源ip地址限制", default="")
parser.add_argument("-mudimac", "--mudimac", help="过滤目的mac限制", default="")
parser.add_argument("-yuanmac", "--yuanmac", help="过滤源mac地址限制", default="")

parser.add_argument("-gaptime", "--gaptime", help="多少秒后停止流量检测", default=60, type=int) # gaptime未完成
parser.add_argument("-save", "--save", help="是否保留这次的检测结果", default=True, type=bool)
parser.add_argument("-keep", "--keep", help="是否紧接着上次的流量检测", default=False, type=bool)

args = parser.parse_args()

devs = pcap.findalldevs()

quit_sniffer = False

print("打印网卡信息，编号为行数，起始编号为0")
print(*devs, sep='\n')

# 应该写一个包

def start_sniffer():
    class Flow(object):
        # 一些输出表示功能
        HISTORYBYTES = []
        YUANIPS = {}
        YUANMACS = {}
        MUDIIPS = {}
        MUDIMACS = {}

        @staticmethod
        def backup():
            backupFlowData ={}
            backupFlowData["HISTORYBATES"] = Flow.HISTORYBYTES
            backupFlowData["YUANIPS"] = Flow.YUANIPS
            backupFlowData["YUANMACS"] = Flow.YUANMACS
            backupFlowData["MUDIIPS"] = Flow.MUDIIPS
            backupFlowData["MUDIMACS"] = Flow.MUDIMACS
            pickle.dump(backupFlowData, open("FlowData.bk", "wb"))
        @staticmethod
        def recoveryHistoryData():
            if os.path.exists("FlowData.bk"):
                backupFlowData = pickle.load(open("FlowData.bk", "rb"))
                Flow.HISTORYBYTES = backupFlowData["HISTORYBATES"]
                Flow.YUANIPS = backupFlowData["YUANIPS"]
                Flow.YUANMACS = backupFlowData["YUANMACS"]
                Flow.MUDIIPS = backupFlowData["MUDIIPS"]
                Flow.MUDIMACS = backupFlowData["MUDIMACS"]

        @staticmethod
        def cleanStatic():
            import os
            os.remove("FlowData.bk")
            Flow.HISTORYBYTES.clear()
            Flow.YUANIPS.clear()
            Flow.YUANMACS.clear()
            Flow.MUDIIPS.clear()
            Flow.MUDIMACS.clear()

        @staticmethod
        def showStatic():
            print("-----------流量统计-------------")
            print("源ip            次数")
            for iter in sorted(Flow.YUANIPS.items(), key=lambda item: item[1], reverse=True):
                print("{:14} {}".format(iter[0], iter[1]))
            print("目的ip          次数")
            for iter in sorted(Flow.MUDIIPS.items(), key=lambda item: item[1], reverse=True):
                print("{:14} {}".format(iter[0], iter[1]))
            print("源mac           次数")
            for iter in sorted(Flow.YUANMACS.items(), key=lambda item: item[1], reverse=True):
                print("{:14} {}".format(iter[0], iter[1]))
            print("目的mac         次数")
            for iter in sorted(Flow.MUDIMACS.items(), key=lambda item: item[1], reverse=True):
                print("{:14} {}".format(iter[0], iter[1]))
            print("-----------流量统计结束---------")
            """
            print("是否清空流量统计器：是 输入1 否，输入0")
            clear_static = input()
            if clear_static=='1':
                flow.cleanStatic()
            """

        @staticmethod
        def trans(s):
            return "%s" % ''.join('%.2x' % x for x in s)

        def __init__(self, pdata):

            self.mudimac = ""
            self.mudiip = ""
            self.yuanmac = ""
            self.yuanip = ""
            self.filter_xieyiS = set()
            self.pdata = pdata
            self.ethernet(self.pdata[1])

        #        if True:
        #            Flow.pdataList.append(pdata)

        # 应用层
        def http(self, bytesdata):
            self.filter_xieyiS.add("http")
            pass

        # 传输层
        def icmp(self, bytesdata):
            self.filter_xieyiS.add("icmp")
            print("？这是一个icmp协议，功能未完成")
            pass

        def tcp(self, bytesdata):
            self.filter_xieyiS.add("tcp")
            self.msg += "传输层\ttcp协议分析开始\n"
            yuanduankou = (bytesdata[0] << 8) + bytesdata[1]
            #    print("源端口为", yuanduankou)
            mudiduankou = (bytesdata[2] << 8) + bytesdata[3]
            #    print("目的端口为", mudiduankou)

            shunxvhao = (bytesdata[4] << 24) + (bytesdata[5] << 16) + (bytesdata[6] << 8) + bytesdata[7]
            #    print("顺序号为", shunxvhao)
            querenhao = (bytesdata[8] << 24) + (bytesdata[9] << 16) + (bytesdata[10] << 8) + bytesdata[11]
            #    print("确认号为", querenhao)
            tcptoubuchang = bytesdata[12] >> 4
            #    print("tcp头部长为", tcptoubuchang)
            urg = (bytesdata[13] & 0b00100000) >> 5
            #    print("urg为", urg)
            ack = (bytesdata[13] & 0b00010000) >> 4
            #    print("ack为", ack)
            psh = (bytesdata[13] & 0b00001000) >> 3
            #    print("psh为", psh)
            rst = (bytesdata[13] & 0b00000100) >> 2
            #    print("rst为", rst)
            syn = (bytesdata[13] & 0b00000010) >> 1
            #    print("syn为", syn)
            fin = (bytesdata[13] & 0b00000001)
            #    print("fin为", fin)
            chuangkoudaxiao = (bytesdata[14] << 8) + bytesdata[15]
            #    print("窗口大小为", chuangkoudaxiao)
            jiaoyanhe = (bytesdata[16] << 8) + bytesdata[17]
            #    print("校验和为", jiaoyanhe)
            jinjizhizhen = (bytesdata[18] << 8) + bytesdata[19]
            #    print("紧急指针为", jinjizhizhen)
            kexuanxiangaddshuju = bytesdata[20:]
            #    print(kexuanxiangaddshuju)

            self.msg += "源端口\t目的端口\t\t顺序号\t\t确认号\turg\tack\tsyn\tfin\n"
            self.msg += "{:5}\t{:5}\t{:11}\t{:11}\t{:1}\t{:1} \t{:1}\t{:1}\n" \
                .format(yuanduankou, mudiduankou, shunxvhao, querenhao, urg, ack, syn, fin)
            self.msg += "-------------------------------------------------------------------------------\n"

        def udp(self, bytesdata):
            self.filter_xieyiS.add("udp")
            self.msg += "传输层\tudp协议\n"
            yuanduankou = (bytesdata[0] << 8) + bytesdata[1]
            mudiduankou = (bytesdata[2] << 8) + bytesdata[3]
            changdu = (bytesdata[4] << 8) + bytesdata[5]
            jiaoyanhe = (bytesdata[6] << 8) + bytesdata[7]
            shuju = bytesdata[8:]
            self.msg += "\t源端口\t目的端口\t\t\t长度\n"
            self.msg += "\t{:5}\t{:5}\t{:11}\n".format(yuanduankou, mudiduankou, changdu)
            self.msg += "-------------------------------------------------------------------------------\n"

        # 网络层
        def rarp(self, bytesdata):
            self.filter_xieyiS.add("rarp")
            print("？这是一个rarp协议，功能未完成")
            pass

        def arp(self, bytesdata):
            self.msg += "网络层\tarp协议分析开始   "
            self.filter_xieyiS.add("arp")
            yingjianleixing = bytesdata[:2]  # 硬件类型
            xieyileixing = bytesdata[2:4]  # 协议类型
            yingjiandizhichangdu = bytesdata[4]  # 硬件地址长度
            xieyidizhichangdu = bytesdata[5]  # 协议地址长度

            fasongzhemac = bytesdata[8:14]  # 发送者mac地址
            self.yuanmac = self.trans(fasongzhemac)
            self.yuanip = "{:3}.{:3}.{:3}.{:3}".format(bytesdata[14], bytesdata[15], bytesdata[16], bytesdata[17]).replace(' ', '')
            mubiaomac = bytesdata[18:24]  # 目标mac地址
            self.mudimac = self.trans(mubiaomac)
            self.mudiip = "{:3}.{:3}.{:3}.{:3}".format(bytesdata[24], bytesdata[25], bytesdata[26], bytesdata[27]).replace(' ', '')

            self.msg += "\t源mac\t\t\t源ip\t\t\t目的mac\t\t\t目的ip\n"
            self.msg += "{:9}\t{:12}\t{:9}\t{:12}\n".format(self.yuanmac, self.yuanip, self.mudimac, self.mudiip)
            self.msg += "-------------------------------------------------------------------------------\n"

        def ip(self, bytesdata):
            self.msg = self.msg + "网络层\tip协议分析\n"
            ipv4_version = bytesdata[0] >> 4  # 占4bits
            header_length = (bytesdata[0] & 0b00001111) * 4  # 占4bits 最大长度为60字节，既15*4*8位=60字节
            serve_type = bytesdata[1]  # 占8bits
            all_length = (bytesdata[2] << 8) + bytesdata[3]  # 占16bits 最大长度为65535字节，即2^16-1=65535。
            biaoshi = (bytesdata[4] << 8) + bytesdata[5]  # 占16bits
            biaozhi = bytesdata[6] >> 5  # 占3bits
            pianpianyi = (bytesdata[6] & 0b00011111) << 8 + bytesdata[7]  # 占13bits
            shengcunzhouqi = bytesdata[8]  # 占8bits
            xieyi = bytesdata[9]  # 占8bits
            toubujiaoyanhe = (bytesdata[10] << 8) + bytesdata[11]  # 占16bits
            yuanip = bytesdata[12:16]  # 占32bits
            mudiip = bytesdata[16:20]  # 占32bits

            xuanxiangaddtianchong = bytesdata[20:header_length]
            shuju = bytesdata[header_length: all_length]

            #    print("ipv4版本为", ipv4_version)
            # print('头部长度为', header_length, "字节")
            #    print('服务类型为', serve_type)
            # print('总长为', all_length, "字节")
            # print('标识为', biaoshi)
            # print('标志为', biaozhi)
            # print('片偏移为', pianpianyi)
            # print('生存周期为', shengcunzhouqi)
            # print('协议为', xieyi)
            #    print('头部校验和为', toubujiaoyanhe)
            self.yuanip = "{:3}.{:3}.{:3}.{:3}".format(yuanip[0], yuanip[1], yuanip[2], yuanip[3]).replace(' ', '')
            self.YUANIPS[self.yuanip] = self.YUANIPS.get(self.yuanip, 0) + 1
            self.mudiip = "{:3}.{:3}.{:3}.{:3}".format(mudiip[0], mudiip[1], mudiip[2], mudiip[3]).replace(' ', '')
            self.MUDIIPS[self.mudiip] = self.MUDIIPS.get(self.mudiip, 0) + 1

            self.msg += "\t头部长度\t\t总长\t标志\t片偏移\t协议号\n"
            self.msg += "\t{:5}\t{:10}\t{:3}\t\t{:3}\t\t{}\n".format(header_length, all_length, biaozhi, pianpianyi,
                                                                     xieyi)
            self.msg += "\t源ip  ：{}\n".format(self.yuanip)
            self.msg += "\t目的ip：{}\n".format(self.mudiip)
            self.msg += "-------------------------------------------------------------------------------\n"

            # 使用的协议
            if xieyi == 1:
                self.icmp(shuju)
            elif xieyi == 6:
                if len(shuju) != 0:
                    self.tcp(shuju)
            elif xieyi == 17:
                if len(shuju) != 0:
                    self.udp(shuju)
            pass

        # 数据链路层
        def ethernet(self, bytesdata):
            self.filter_xieyiS.add("")
            self.yuanmac = self.trans(bytesdata[0:6])
            self.YUANMACS[self.yuanmac] = self.YUANMACS.get(self.yuanmac, 0) + 1
            self.mudimac = self.trans(bytesdata[6:12])
            self.MUDIMACS[self.mudimac] = self.MUDIMACS.get(self.mudimac, 0) + 1

            self.msg = "********************************************************************************\n"
            self.msg += "数据链路层分析\n"
            self.msg += "\t源mac\t\t\t目的mac\n"
            self.msg += "\t{:13}\t{:13}\n".format(self.yuanmac, self.mudimac)
            self.msg += "-------------------------------------------------------------------------------\n"
            if bytesdata[12:14] == b'\x08\x00':
                self.ip(bytesdata[14:])
            # ARP
            elif bytesdata[12:14] == b'\x08\x06':
                self.arp(bytesdata[14:])
            # RARP
            elif bytesdata[12:14] == b'\x08\x35':
                self.rarp(bytesdata[14:])
            return
    fxieyi = args.xieyi
    fmudiip = args.mudiip
    fyuanip = args.yuanip
    fmudimac = args.mudimac
    fyuanmac = args.yuanmac
    gaptime = args.gaptime
    save = args.save
    keep = args.keep
    if keep:
        Flow.recoveryHistoryData()
    else:
        if os.path.exists("FlowData.bk"):
            os.remove("FlowData.bk")
    pc = pcap.pcap(devs[-4], promisc=True, immediate=True)


    for pdata in pc:
        if quit_sniffer:
            break
        flow = Flow(pdata)
        if (fxieyi in flow.filter_xieyiS) and (fyuanip=="" or fyuanip==flow.yuanip) and (fmudiip=="" or fmudiip==flow.mudiip) \
                and (fyuanmac=="" or fyuanmac==flow.mudimac) and (fmudimac=="" or fmudimac==flow.mudimac):
            Flow.HISTORYBYTES.append(pdata)
            print(flow.msg)
    if save:
        Flow.backup()
    Flow.showStatic()
    print("感谢您使用SnifferPy工具。")
    return

if __name__ == '__main__':
    sniffer = threading.Thread(target=start_sniffer)
    sniffer.start()
    if input() != None:
        quit_sniffer = True
