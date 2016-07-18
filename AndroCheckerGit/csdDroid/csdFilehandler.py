import sys, os, cmd, threading, code, re, traceback, time, signal

from optparse import OptionParser

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
#from androguard.core.bytecodes.jd import *
#from androguard.core.bytecodes.dd import *
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *

from androguard.core import androconf
from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config
from cPickle import dumps, loads
from androlyze import AnalyzeAPK

import csdConf
import copy 


def get_listener_params():
    ret_listener_list = []
    with open(csdConf.unobslist_file, 'r') as f:
        for line in f.readlines():
            if line.find("(")>-1 and line.find(")")>-1:
                params = line[line.find("(")+1: line.find(")")]
            if params.find("Listener")>-1:
                key_params = params[params.rfind(" ",params.find("Listener")):]
                
def get_method_traces_statisc(meterial_path):
    ret = {}
    
    TOTAL_SINK = {} # SINK_NAME1 : NUM ; SINK_NAME2 : NUM; ````
    TOTAL_KEY_COMPONENT = {} # KEY_COMPONENT_NAME1 : NUM ;KEY_COMPONENT_NAME2 : NUM
    TOTAL_PEC = {} # PEC_NAME1 : NUM ;PEC_NAME2 : NUM
    APK = {} # PEC_THREATS:NUM
    
    TOTAL_DETECTED_NUM =0
    
    
    TOTAL_COMPONENTS ={} # ACTIVITY: NUM; SERVICE: NUM ; BROADCASTRECEIVER: NUM 
    
    APK_NAME = ""
    with open (meterial_path,'r') as f:
        line = f.readline()
        print line +"\n"
        while line:
            
            
            if line.find("[APK]")>-1:
                APK_NAME = line[line.find("[APK]") + 5: -1]
                APK[APK_NAME] = {}
                APK[APK_NAME]["THREATS"] = 0
                APK[APK_NAME]["ACTIVITY_NUM"] = 0
                APK[APK_NAME]["SERVICE_NUM"] = 0
                APK[APK_NAME]["BROADCASTRECEIVER_NUM"] = 0
                APK[APK_NAME]["PROVIDER_NUM"] = 0
                
                method_name = ""
                TOTAL_DETECTED_NUM = TOTAL_DETECTED_NUM +1
                
            elif line.find("[SINK]")>-1:
                SINK_NAME = line[line.find("[SINK]") + 7: -1]
                if not SINK_NAME in TOTAL_SINK.keys() :
                    TOTAL_SINK[SINK_NAME] = 1
                else : 
                    TOTAL_SINK[SINK_NAME] = TOTAL_SINK[SINK_NAME] +1
                APK[APK_NAME]["THREATS"]= APK[APK_NAME]["THREATS"] +1
                    
            elif line.find("[key_component]")>-1:
                
                KEY_COMPONENT_NAME = line[line.find("[key_component]") + 16: -1]
                if not KEY_COMPONENT_NAME in TOTAL_KEY_COMPONENT.keys() :
                    TOTAL_KEY_COMPONENT[KEY_COMPONENT_NAME] = 1
                else : 
                    TOTAL_KEY_COMPONENT[KEY_COMPONENT_NAME] = TOTAL_KEY_COMPONENT[KEY_COMPONENT_NAME] +1 
                    
                # handle method_path(PEC), because key_component follows the last one of method_paths
                if not method_name in TOTAL_PEC.keys():
                    TOTAL_PEC[method_name]  = 1
                else : 
                    TOTAL_PEC[method_name] = TOTAL_PEC[method_name] +1
                    
            elif line.find("[acitivity_num]")>-1:
                APK[APK_NAME]["ACTIVITY_NUM"] = string.atoi(line[line.find("[acitivity_num]") + 15: -1])
                if not "ACTIVITY_NUM" in TOTAL_COMPONENTS.keys():
                    TOTAL_COMPONENTS["ACTIVITY_NUM"] = APK[APK_NAME]["ACTIVITY_NUM"]
                else :                    
                    TOTAL_COMPONENTS["ACTIVITY_NUM"] = TOTAL_COMPONENTS["ACTIVITY_NUM"] + APK[APK_NAME]["ACTIVITY_NUM"]
            elif line.find("[service_num]")>-1:
                APK[APK_NAME]["SERVICE_NUM"] = string.atoi(line[line.find("[service_num]") + 13: -1])
                if not "SERVICE_NUM" in TOTAL_COMPONENTS.keys():
                    TOTAL_COMPONENTS["SERVICE_NUM"] = APK[APK_NAME]["SERVICE_NUM"]
                else :                    
                    TOTAL_COMPONENTS["SERVICE_NUM"] = TOTAL_COMPONENTS["SERVICE_NUM"] + APK[APK_NAME]["SERVICE_NUM"]  
            elif line.find("[broadcastreceiver_num]")>-1:
                #print "broadcastreceiver_num  " + line[line.find("[broadcastreceiver_num]") + 23: -1] + "\n"
                APK[APK_NAME]["BROADCASTRECEIVER_NUM"] = string.atoi(line[line.find("[broadcastreceiver_num]") + 23: -1])
                if not "BROADCASTRECEIVER_NUM" in TOTAL_COMPONENTS.keys():
                    TOTAL_COMPONENTS["BROADCASTRECEIVER_NUM"] = APK[APK_NAME]["BROADCASTRECEIVER_NUM"]
                else :                    
                    TOTAL_COMPONENTS["BROADCASTRECEIVER_NUM"] = TOTAL_COMPONENTS["BROADCASTRECEIVER_NUM"] + APK[APK_NAME]["BROADCASTRECEIVER_NUM"]                     
            elif line.find("[provider_num]")>-1:
                #print "provider_num  "+line[line.find("[provider_num]") + 14: -1]+"\n"
                APK[APK_NAME]["PROVIDER_NUM"] = string.atoi(line[line.find("[provider_num]") + 14: -1])
                if not "PROVIDER_NUM" in TOTAL_COMPONENTS.keys():
                    TOTAL_COMPONENTS["PROVIDER_NUM"] = APK[APK_NAME]["PROVIDER_NUM"]
                else :                    
                    TOTAL_COMPONENTS["PROVIDER_NUM"] = TOTAL_COMPONENTS["PROVIDER_NUM"] + APK[APK_NAME]["PROVIDER_NUM"] 
            elif line.find("[method_path]")>-1:  
                method_name = line[line.find(":")+1: -1]
                
            else : pass
            
            line = f.readline()
                    
    ret["TOTAL_SINK"] = TOTAL_SINK
    ret["TOTAL_KEY_COMPONENT"] = TOTAL_KEY_COMPONENT
    ret["APK"] = APK
    ret["TOTAL_COMPONENTS"] = TOTAL_COMPONENTS
    ret["TOTAL_PEC"] = TOTAL_PEC
    ret["TOTAL_DETECTED_NUM"] = TOTAL_DETECTED_NUM
    
    return ret

def select_final_data(meterial_path, new_meterial_path):
    remove_method = ["run","getTokenWithNotification","handleMessage","doInBackground",
                     "onKeyDown","onPostExecute","onOptionsItemSelected",
                     "onTouch",
                     
                     'q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','Q','W','E','R','T','Y','U','I','O','P','A','S','D','F','G','H','J','K','L','Z','X','C','V','B','N','M','ag','zza',"zzb"]
    
    tmp = []
    
    total_tmp = []
    
    with open (meterial_path,'r') as f:
            
            line = f.readline()
            #print line +"\n"
            while line: 
                print "total_tmp_len: " + str(len(total_tmp)) +"\n"
                if line.find("[APK]")>-1:
                    method_name = ""
                    
                    if str(tmp).find("SINK")>-1:
                        for t in tmp:
                            total_tmp.append(t)
                    
                    tmp=[]
                    tmp.append(line)
                    
                elif line.find("[key_component]")>-1:
                    tmp.append(line)
                    for r in remove_method:
                        if r==method_name:
                            
                            #print "(0)tmp :" + str(tmp) + "\n"
                            while tmp:
                                last = tmp[-1]
                                if not last.find("SINK")>-1:
                                    tmp.pop()
                                else:
                                    #print "(1)tmp :" + str(tmp) + "\n"
                                    tmp.pop()
                                    break
                    
                elif line.find("[method_path]")>-1: 
                    tmp.append(line)
                    method_name = line[line.find(":")+1: -1] 
                    
                else:
                    tmp.append(line)
                    
                line = f.readline()
                    
    with open (new_meterial_path,'a') as nf:  
        for to in total_tmp:
            nf.write(to)
                        
                
                
if __name__ == '__main__':
    
    meterial_path = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/mtrace_result_path_total2.txt"
    new_meterial_path = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/mtrace_result_path_total2_new.txt"
    
    #select_final_data(meterial_path, new_meterial_path)
    
    
    
    ret = get_method_traces_statisc(new_meterial_path)
    
    
    print "TOTAL_DETECTED_NUM" + str(ret["TOTAL_DETECTED_NUM"])+"\n"
    print "TOTAL_SINK:  " + str(ret["TOTAL_SINK"]) +"\n"
    print "TOTAL_KEY_COMPONENT:  " + str(ret["TOTAL_KEY_COMPONENT"]) +"\n"    
    print "TOTAL_COMPONENTS:  " + str(ret["TOTAL_COMPONENTS"]) +"\n"
    print "TOTAL_PEC:  " + str(sorted(ret["TOTAL_PEC"].iteritems(), key=lambda d:d[1], reverse = True)) +"\n"  #sort from big to small

    print "APK:  " + str(ret["APK"]) +"\n"