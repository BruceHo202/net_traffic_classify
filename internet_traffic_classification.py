import os
import time
import numpy as np
import sklearn
import scapy
import struct
from scapy.all import *
from scapy.utils import PcapReader
from decimal import Decimal
from sklearn.utils import Bunch
from sklearn.preprocessing import StandardScaler
from tools import writebunchobj,readbunchobj,readLine,savefile,readfile,readcsv
from sklearn.model_selection import GridSearchCV    
from sklearn.svm import SVC  
from sklearn import svm 
import sklearn.tree as st
import sklearn.ensemble as se
from sklearn import metrics
import pandas as pd
import warnings
import sklearn.exceptions
warnings.filterwarnings("ignore", category=sklearn.exceptions.UndefinedMetricWarning)
warnings.filterwarnings("ignore")

beginTime = 0

all_kind = ['Audio_Streaming','Browsing','Chat','Email','File_Transfer','P2P','Video_Streaming','VoIP']
timestamps = []
limit = 100000
count = 0
FEATURE_NUM = 5 + 1 + 3 + 34 + 2 + 8
# TCP、UDP、ICMP、ARP、DNS比例
# 包个数
# 平均、最大、最小包长度
# 每种协议是否存在
# 最短时间间隔，最长时间间隔
# 是否可能是某一类
PROTOCOL_NUM = 5 # TCP、UDP、ICMP、ARP、DNS
ALL_PROTOCOL_NUM = 34

    #ARP、TCP、UDP、XMPP/XML、HTTP/XML、ICMP、DNS、HTTP、ICMP、 9
    #SSLv2、TLSv1.2、OCSP、TLSv1、WebSocket、HTTP/JSON、TLSv1.1、 7
    #FTP、FTP-DATA、SSHv2、SSH、BAT_VIS、BitTorrent、IGMPv3、 7
    #GQUIC、STUN、SSL、RTCP、TURN Channel、BFD Echo、DTLS、SSDP、NAT-PMP、WOW、IRC 11
def time_stmp(pkt):
    global count, limit, timestamps
    timestamps.append(str(pkt.time))
    count += 1
    if limit > 0 and count >= limit:
        return True
    else:
        return False

def make_file_mat(dat_file_dir, file_dir):
    global count, limit, timestamps
    time1 = time.process_time()
    packets = PcapReader(file_dir)
    packets = list(packets)
    count = 0
    limit = len(packets)
    print(file_dir)
    print('------', limit)
    print('该文件执行时间: %s s' % (time.process_time() - time1))
    print('已执行时间: %s s' % (time.process_time() - beginTime))
    timestamps = []
    sniff(offline=file_dir, stop_filter=time_stmp, store=False)


    dat_file_dir = dat_file_dir[:-4] + 'dat'
    bunch = Bunch(packets=[],timestamps=[])
    bunch.packets.extend(packets)
    bunch.timestamps.extend(timestamps)
 #   print("timestamps length=",len(bunch.timestamps))
    writebunchobj(dat_file_dir,bunch)

def make_mat(root_dir,file_path,dat_root_dir):
    
    global beginTime
    kindlist = os.listdir(root_dir)
    kind_cnt = len(kindlist)
    for kind in kindlist:
        cur_dir = root_dir + kind + '/'
        dat_cur_dir = dat_root_dir + kind + '/'
        file_list = os.listdir(cur_dir)
        if not os.path.exists(dat_cur_dir):
            os.makedirs(dat_cur_dir)
        for file in file_list:

            file_dir = cur_dir + file
            dat_file_dir = dat_cur_dir + file
            make_file_mat(dat_file_dir,file_dir)
            

def grade_mode(list):
    list_set=set(list) #取list的集合，去除重复元素
    frequency_dict={}
    for i in list_set:#遍历每一个list的元素，得到该元素何其对应的个数.count(i)
        frequency_dict[i]=list.count(i)#创建dict; new_dict[key]=value
    grade_mode = 0
    # dict_lis = list(frequency_dict.keys())
    # value_lis = list(frequency_dict.values())
    # grade_mode = dict_lis[value_lis.index(max(frequency_dict.values()))]
    for key,value in frequency_dict.items():
        if value == max(frequency_dict.values()):
            grade_mode = key
            break
    return grade_mode

def maxAppear(list):
    list_set = set(list) #取list的集合，去除重复元素
    frequency_dict = {}
    for i in list_set:#遍历每一个list的元素，得到该元素何其对应的个数.count(i)
        frequency_dict[i] = list.count(i)#创建dict; new_dict[key]=value
    
    lis_order = sorted(frequency_dict.items(), key = lambda x:x[1], reverse = True)
    return lis_order[0][0], lis_order[1][0], lis_order[2][0], lis_order[3][0], lis_order[4][0]

def cut_time_slot_each(csv_file_path,feature_mat,label, TIME_SLOT, kind):
    portNameList = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP']
    ALLportNameList = ['ARP','TCP','UDP','XMPP/XML','HTTP/XML','ICMP','DNS','HTTP','ICMP',
                    'SSLv2','TLSv1.2','OCSP','TLSv1','WebSocket','HTTP/JSON','TLSv1.1',
                    'FTP','FTP-DATA','SSHv2','SSH','BAT_VIS','BitTorrent','IGMPv3',
                    'GQUIC','STUN','SSL','RTCP','TURN Channel','BFD Echo','TLS','SSDP','NAT-PMP','WOW','IRC']

    sportTotCount = []
    dportTotCount = []
    protocol_flag = []
    for i in range(ALL_PROTOCOL_NUM):
        protocol_flag.append(0)

    pcap = readcsv(csv_file_path)
    t_start = pcap.iloc[0]['Time']
            # s_port_lis = []
            # d_port_lis = []

    numPort = np.zeros(PROTOCOL_NUM)
    totNum = 0 # 总的包个数
    totPortNum = 0 # 五种协议的总个数
    maxPacketLen = 0 # 最大包长度
    minPacketLen = 2147483647 # 最小包长度
    totPacketLen = 0 # 平均包长度
    minPacketInterval = 2147483647 # 最短时间间隔
    maxPacketInterval = 0 # 最长时间间隔
    k = 0
    all_time = pcap.iloc[len(pcap)-1]['Time'] - pcap.iloc[0]['Time']
    p_per_s = len(pcap)/all_time
    print(p_per_s,all_time,pcap.iloc[len(pcap)-1]['Time'],pcap.iloc[0]['Time'],len(pcap))
    while k < len(pcap):
                # print(len(all_packets[i][j]), len(all_time_stamps[i][j]))
                # print('\n')
       # print("k=",k)
        if pcap.iloc[k]['Time'] - t_start <= TIME_SLOT:
            totPacketLen += pcap.iloc[k]['Length']
            maxPacketLen = max(maxPacketLen, pcap.iloc[k]['Length'])
            minPacketLen = min(minPacketLen, pcap.iloc[k]['Length'])

            totNum += 1
            protocol = pcap.iloc[k]['Protocol']
            this_time = pcap.iloc[k]['Time']
            if this_time != t_start:
                interval = this_time - t_start
                if interval < minPacketInterval:
                    minPacketInterval = interval
                if interval > maxPacketInterval:
                    maxPacketInterval = interval
            for xx in range(PROTOCOL_NUM):
                if portNameList[xx] == protocol:
                    numPort[xx] += 1
                    totPortNum += 1
                    break
            for xx in range(ALL_PROTOCOL_NUM):
                if ALLportNameList[xx] == protocol:
                    protocol_flag[xx] = 1
                    break
            k += 1
        else:
            #print("k=",k,"totPortNum=",totPortNum,"pcap.iloc[k]['Time']=",pcap.iloc[k]['Time'],"t_start=",t_start)
            this_feature = [0 for i in range(FEATURE_NUM)]
            for xx in range(PROTOCOL_NUM): # 1、时间片中各协议的比例：ARP、TCP、UDP、ICMP、DNS'
                this_feature[xx] = 1.0 * numPort[xx] / totPortNum

            this_feature[PROTOCOL_NUM] = totNum / TIME_SLOT # 2、时间片中包个数

            this_feature[PROTOCOL_NUM + 1] = 1.0 * totPacketLen / totNum # 3、平均、最大、最小包长度
            this_feature[PROTOCOL_NUM + 2] = maxPacketLen 
            this_feature[PROTOCOL_NUM + 3] = minPacketLen
            for xx in range(ALL_PROTOCOL_NUM):
                this_feature[PROTOCOL_NUM + 4 + xx] = protocol_flag[xx]
            this_feature[PROTOCOL_NUM + ALL_PROTOCOL_NUM + 3 + 1] = minPacketInterval
            this_feature[PROTOCOL_NUM + ALL_PROTOCOL_NUM + 3 + 2] = maxPacketInterval
            index = PROTOCOL_NUM + ALL_PROTOCOL_NUM + 3 + 3
            for xx in range(len(all_kind)):
                this_feature[index + xx] = 0
                '''
                if xx == 0:
                    continue
                elif xx == 1:
                    if this_feature[PROTOCOL_NUM + 4 + 14] == 1 or this_feature[PROTOCOL_NUM + 4 + 13] == 1 :
                        this_feature[index + xx] = 100
                    #if this_feature[index + xx] == 0:
                    #    if this_feature[PROTOCOL_NUM + 4 + 10] == 1 and totNum < 300:
                    #        this_feature[index + xx] = 100
                elif xx == 2:
                    if this_feature[PROTOCOL_NUM + 4 + 3] == 1 or this_feature[PROTOCOL_NUM + 4 + 33] == 1:
                        this_feature[index + xx] = 100
                elif xx == 3:
                    continue
                elif xx == 4:
                    if this_feature[PROTOCOL_NUM + 4 + 16] == 1 or this_feature[PROTOCOL_NUM + 4 + 17] == 1 or this_feature[PROTOCOL_NUM + 4 + 18] or this_feature[PROTOCOL_NUM + 4 + 20]:
                        this_feature[index + xx] = 100
                elif xx == 5:
                    if this_feature[PROTOCOL_NUM + 4 + 21]:
                        this_feature[index + xx] = 100
                elif xx == 6:
                    if kind == "Video_Streaming":
                        print("kind=",kind,"this_feature[PROTOCOL_NUM + 4 + 10]=",this_feature[PROTOCOL_NUM + 4 + 10],"totNum/TIME_SLOT=",totNum/TIME_SLOT)
                    if this_feature[PROTOCOL_NUM + 4 + 10] == 1 and totNum/TIME_SLOT > 200:
                        this_feature[index + xx] = 100
                elif xx == 7:
                    if this_feature[PROTOCOL_NUM + 4 + 24] == 1 or this_feature[PROTOCOL_NUM + 4 + 28] == 1 or this_feature[PROTOCOL_NUM + 4 + 31] or this_feature[PROTOCOL_NUM + 4 + 32]:
                        this_feature[index + xx] = 100
                '''

           # print(kind,":")
            if this_feature[PROTOCOL_NUM + 4 + 14] == 1 or this_feature[PROTOCOL_NUM + 4 + 13] == 1 : # 1
                this_feature[index + 1] = 100
              #  print(kind,"1")
            elif this_feature[PROTOCOL_NUM + 4 + 3] == 1 or this_feature[PROTOCOL_NUM + 4 + 33] == 1: # 2
                this_feature[index + 2] = 100
              #  print(kind,"2.0")
            elif this_feature[PROTOCOL_NUM + 4 + 16] == 1 or this_feature[PROTOCOL_NUM + 4 + 17] == 1 or this_feature[PROTOCOL_NUM + 4 + 18] or this_feature[PROTOCOL_NUM + 4 + 20]: # 4
                this_feature[index + 4] = 100
               # print(kind,"4")
            elif this_feature[PROTOCOL_NUM + 4 + 21]: # 5
                this_feature[index + 5] = 100
               # print(kind,"5")
            elif this_feature[PROTOCOL_NUM + 4 + 24] == 1 or this_feature[PROTOCOL_NUM + 4 + 28] == 1 or this_feature[PROTOCOL_NUM + 4 + 31] or this_feature[PROTOCOL_NUM + 4 + 32]: # 7
                this_feature[index + 7] = 100
               # print(kind,"7")
            elif this_feature[PROTOCOL_NUM + 4 + 15] == 0 and this_feature[PROTOCOL_NUM + 4 + 10] == 0 and this_feature[PROTOCOL_NUM + 4 + 0] == 0: # 0
                this_feature[index + 0] = 100
               # print(kind,"0")
            elif this_feature[PROTOCOL_NUM + 4 + 15] == 1 and p_per_s > 50: # 6
                this_feature[index + 6] = 100
               # print(kind,"6")
            elif this_feature[PROTOCOL_NUM + 4 + 15] == 1 and p_per_s < 50: # 2
                this_feature[index + 2] = 100
                #print(kind,"2")

            
            t_start = pcap.iloc[k]['Time']

            numPort = np.zeros(PROTOCOL_NUM)
            totNum = 0
            totPortNum = 0
            maxPacketLen = 0 # 最大包长度
            minPacketLen = 2147483647 # 最小包长度
            totPacketLen = 0 # 平均包长度
            minPacketInterval = 2145483547 # 最短时间间隔
            maxPacketInterval = 0 # 最长时间间隔
            #protocol_flag = []
            #for i in range(ALL_PROTOCOL_NUM):
                #protocol_flag.append(0)
            feature_mat.append(this_feature)
            label.append(kind)

def cut_time_slot(csv_root_path,feature_dat_path,TIME_SLOT):
    
    
    feature_mat = []
    label = []
    kindlist = os.listdir(csv_root_path)
    kind_cnt = len(kindlist)
    for kind in kindlist:

        csv_cur_path = csv_root_path + kind +'/'
        csv_file_list = os.listdir(csv_cur_path)

        for csv_file in csv_file_list:
            csv_file_path = csv_cur_path + csv_file
            time1 = time.process_time()
            cut_time_slot_each(csv_file_path,feature_mat,label, TIME_SLOT, kind)
            
            print(csv_file)
            print('该文件执行时间: %s s' % (time.process_time() - time1))
            print('已执行时间: %s s' % (time.process_time() - beginTime))

    new_bunch = Bunch(feature_mat=[],label=[])
    new_bunch.feature_mat.extend(feature_mat)
    new_bunch.label.extend(label)
#    print("feature_mat=",feature_mat)
#    print(new_bunch.feature_mat)
#    print(new_bunch.label)
    writebunchobj(feature_dat_path,new_bunch)


def metrics_result(actual, predict):
    print('正确:{0:.3f}'.format(metrics.accuracy_score(actual, predict)))
    #print('精度:{0:.3f}'.format(metrics.precision_score(actual, predict, average='weighted')))
    #print('召回:{0:0.3f}'.format(metrics.recall_score(actual, predict, average='weighted')))
    #print('f1-score:{0:.3f}'.format(metrics.f1_score(actual, predict, average='weighted')))
    c_m = metrics.confusion_matrix(actual,predict)
    for i in range(len(c_m)):
        num = 0
        for j in range(len(c_m[i])):
            num += c_m[i][j]
        for j in range(len(c_m[i])):
            c = str(c_m[i][j]/num * 100)[:4]+ '%'
            print(c,"\t",end="")
        print()

def SVM(train_dat_path,test_dat_path):

    bunch = readbunchobj(train_dat_path)
    label_0 = bunch.label
    label = []
    #print(len(label_0))
    for i in range(len(label_0)):
        for xx in range(len(all_kind)):
            if label_0[i] == all_kind[xx]:
                label.append(xx)
                #print(all_kind[xx])
    #print(len(label))
    feature = np.array(bunch.feature_mat)
    bunch = readbunchobj(test_dat_path)
    test_label_0 = bunch.label
    #print(len(test_label_0))
    test_label = []
    for i in range(len(test_label_0)):
        for xx in range(len(all_kind)):
            if test_label_0[i] == all_kind[xx]:
                test_label.append(xx)
    test_feature = np.array(bunch.feature_mat)
   # for i in range(len(test_feature)):
       # print(test_label[i])
      #  for xx in range(len(all_kind)):
       #     print(test_feature[i][PROTOCOL_NUM + ALL_PROTOCOL_NUM + 3 + 3 + xx])
       # print("=============")
 #   print(len(feature))
    #model = SVC(kernel='rbf', probability=True)    
    #param_grid = {'C': [1e-3, 1e-2, 1e-1, 1, 10, 100, 1000], 'gamma': [0.001, 0.0001]}    
    #grid_search = GridSearchCV(model, param_grid, n_jobs = 1, verbose=1)    
    #grid_search.fit(feature, label)    
    print("======")
    #best_parameters = grid_search.best_estimator_.get_params()    
    #for para, val in list(best_parameters.items()):    
    #    print(para, val)    
    #classific = SVC(kernel='rbf', C=1.0 , probability=True)    
    #classific.fit(feature, label) 
    classific = svm.SVC(C=1, kernel='linear', decision_function_shape='ovr').fit(feature,label)
    #scaler = StandardScaler()
    #feature = scaler.fit_transform(feature)
    #test_feature = scaler.fit_transform(test_feature)
    #classific = st.DecisionTreeRegressor(max_depth = 7)
    #classific = se.AdaBoostRegressor(classific, n_estimators=1500, random_state=10)
    classific.fit(feature,label)
    predict_0 = classific.predict(test_feature)
    #print(len(predict_0))
    predict= []
    for i in range(len(predict_0)):
        predict.append(int(predict_0[i]))
        #for xx in range(len(all_kind)):
            #if test_feature[i][PROTOCOL_NUM + ALL_PROTOCOL_NUM + 3 + 3 + xx] == 100.0:
                #predict[i] = xx
        #print(predict[i],test_label[i])
    #print(predict)

    metrics_result(test_label,predict)



if __name__ == '__main__':

    beginTime = time.process_time()
    
    # '''
    # 训练集转为dat
    # '''
    # root_dir = './TrainingSets/'
    # file_path = './training_sets.txt'
    # dat_root_dir = './TrainingSetsDat/'
    # if not os.path.exists(dat_root_dir):
    #         os.makedirs(dat_root_dir)
    # make_mat(root_dir, file_path,dat_root_dir)
    
    # endTime = time.process_time()
    # print('总运行时间: %s s' % (endTime - beginTime))

    # '''
    # 测试集转为dat
    # '''
    # root_dir = './TestSets/'
    # file_path = './testsets.txt'
    # dat_root_dir = './TestSetsDat/'
    # if not os.path.exists(dat_root_dir):
    #         os.makedirs(dat_root_dir)
    # make_mat(root_dir, file_path,dat_root_dir)
    
    #endTime = time.process_time()
    #print('总运行时间: %s s' % (endTime - beginTime))
    

    '''
  # 训练集csv读取并转为特征矩阵
    
    csv_root_dir = './SmallTrainingSetsCSV/'
    feature_dat_path = './feature.dat'
    cut_time_slot(csv_root_dir,feature_dat_path,10)

    endTime = time.process_time()
    print('训练集转特征矩阵时间: %s s' % (endTime - beginTime))
    '''
    '''
  #  测试集csv转为特征矩阵
    
    dat_root_dir = './SmallTestSetsCSV/'
    feature_dat_path = './feature_test.dat'
    cut_time_slot(dat_root_dir,feature_dat_path,10)

    
    endTime2 = time.process_time()
    print('测试集转特征矩阵时间: %s s' % (endTime2 - endTime))
    print('总运行时间: %s s' % (endTime2 - beginTime))
    '''
    '''
    学习与预测过程
    '''
    train_dat_path = './feature.dat'
    test_dat_path = './feature_test.dat'
    SVM(train_dat_path,test_dat_path)
