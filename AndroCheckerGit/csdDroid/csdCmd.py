import sys, os, cmd, threading, code, re, traceback
import csdAnalysis 
import csdBlockAnalysis
import csdCollectionAnalysis
import csdGlobal
import getopt
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

import signal
import csdConf
import time


def servicewithsink_dir(directory):
    
    #print postfix
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            #postfix = f[f.rfind(".")+1:]
            apkPath = os.path.join(root,f)
            target_file = csdConf.record_keycomponenttrace_dir +  apkPath[apkPath.rfind("/"): ] + ".txt"
            
            #target_file = csdConf.mtrace_result_path
            def handler(signum, frame):
                print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n"
                with open(target_file, "a") as f:
                    f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                raise AssertionError  
            
            try:
                #timeout-machanism
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(csdConf.time_out)
                
                start = time.clock()     
                
                print "=====================================\n"
                print "[START] "+ apkPath +"\n"
                print "=====================================\n" 
                
                apk,d,inputDex = AnalyzeAPK(apkPath)
                
                mid = time.clock()
                                    
                with open(target_file, "a") as f:
                    f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                print "[time] Parse time is "+ str(mid-start) +"\n"  
                                    
                c, ret = csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex),csdConf.first_state_class, True)
                
                
                end = time.clock()
                with open(target_file, "a") as f:
                    f.write("[time] Main_If_Servicewithsink time is "+ str(end - mid) +"\n")
                    f.write("[time] Total time is "+ str(end - start) +"\n")                        
                    f.write("====================================================\n")
                    ##f.write("[apk_package] "+ str(ret[0]) +"\n")
                    ##f.write("[sink_dict] "+ str(ret[1])+"\n")
                    ##f.write("[key_component] "+ str(ret[3])+"\n")
                    ##f.write("[method_path]: \n")
                    ##if ret[2]!= None and len(ret[2])>0:
                        ##for method in ret[2]:
                            ##f.write("  [method] "+ method.get_name()+" --> ")
                    for ret_elem in ret :
                        # ret_elem[0] == apk.get_package()
                        # ret_elem[1] == sink_dict
                        # ret_elem[2] == method_path
                        # ret_elem[3] == key_component                            
                        f.write("--[service_find_sink] (sink:"+ str(c.Sink2sinkstring(ret_elem[1])) +") \n")
                        f.write("----[method_path]: ") 
                        for m in ret_elem[2]:
                            f.write("(m)"+ m.get_name()+", " )                        
                    
                print "[time] Main_If_Servicewithsink time is "+ str(end - mid) +"\n"
                print "[time] Total time is "+ str(end - start) +"\n"
                print "====================================================\n"
                 
                signal.alarm(0)      
                
                #apk,d,inputDex = AnalyzeAPK(abs_f)
                #csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex))
            except Exception, e:
                with open(target_file, "a") as f:
                    f.write("[ERROR]: app:"+ apkPath +"\n")
                    f.write(traceback.format_exc() +"\n")   
                    
                print "[ERROR]: app:"+ str(apkPath) +"\n"
                traceback.print_exc() 
            
            
            #if postfix == "apk" :   
                #abs_f = os.path.join(root,f)
                ##print "apk:  "+os.path.join(root,f) +"\n"
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(abs_f, "apk")  
                #csdAnalysis.Main_If_Servicewithsink(abs_f, "apk")
            #elif postfix == "dex" : 
                #abs_f = os.path.join(root,f)
                ##print "dex:  "+os.path.join(root,f) +"\n"
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(abs_f, "dex")
                #csdAnalysis.Main_If_Servicewithsink(abs_f, "dex")
            #else:
                #continue
            #print os.path.join(root, f)   
            
def pathfromsourcetosink_dir(directory):
    #target_file = csdConf.record_methodtrace_dir +  apkPath[apkPath.rfind("/"):] + ".txt"
    #print postfix
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            abs_f = os.path.join(root,f)
            try:
                apk,d,inputDex = AnalyzeAPK(abs_f)
                csdAnalysis.Main_BackTrace_Source((apk,d,inputDex)) 
            except Exception, e:
                print "[ERROR]: app:"+ str(abs_f) +"\n"
                traceback.print_exc() 
            
                       
            #postfix = f[f.rfind(".")+1:]
            #if postfix == "apk" :   
                #abs_f = os.path.join(root,f)
                ##print "apk:  "+os.path.join(root,f) +"\n"
                #csdAnalysis.Main_BackTrace_Source(abs_f, "apk")  
            #elif postfix == "dex" : 
                #abs_f = os.path.join(root,f)
                ##print "dex:  "+os.path.join(root,f) +"\n"
                #csdAnalysis.Main_BackTrace_Source(abs_f, "dex")
            #else:
                #continue
            
def collectconditionblock_dir(directory):
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            apkPath = os.path.join(root,f)
            target_file = csdConf.record_collect_dir +  apkPath[apkPath.rfind("/"): ] + ".txt"
            def handler(signum, frame):
                print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec ]\n"
                with open(target_file, "a") as f:
                    f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                raise AssertionError  
                
            
            try:
                #timeout-machanism
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(csdConf.time_out)
                
                start = time.clock()   
                
                print "=====================================\n"
                print "[START] "+ apkPath +"\n"
                print "=====================================\n"  
                
                apk,d,inputDex = AnalyzeAPK(apkPath)
                
                mid = time.clock()
                                    
                with open(target_file, "a") as f:
                    f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                print "[time] Parse time is "+ str(mid-start) +"\n" 
                
                csdBlock, ret_total_collect = csdBlockAnalysis.Main_Collect((apk,d,inputDex))
                
                end = time.clock()
                with open(target_file, "a") as f:
                    f.write("[time] Main_Collect time is "+ str(end - mid) +"\n")
                    f.write("[time] Total time is "+ str(end - start) +"\n")
                    f.write("===================================================\n")
                    
                if ret_total_collect["total_collect_set"]!=None and\
                   len(ret_total_collect["total_collect_set"])>0:
                    for item in ret_total_collect["total_collect_set"]:
                            csdCollectionAnalysis.record_collect_set(ret_total_collect["total_collect_set"][item],
                                                        target_file)
                
                print "[time] Main_Collect time is "+ str(end - mid) +"\n"
                print "[time] Total time is "+ str(end - start) +"\n"
                                    
                signal.alarm(0)  
                
                #apk,d,inputDex = AnalyzeAPK(abs_f)
                #csdAnalysis.Main_Collect((apk,d,inputDex))
            except Exception, e:
                with open(target_file, "a") as f:
                    f.write("[ERROR]: app:"+ apkPath +"\n")
                    f.write(traceback.format_exc() +"\n")   
                    
                print "[ERROR]: app:"+ str(apkPath) +"\n"
                traceback.print_exc() 
             
            
def globalvuls_dir(directory):
    
    
    list_dirs = os.walk(directory) 
    
    for root, dirs, files in list_dirs: 
        #for d in dirs: 
            #print os.path.join(root, d)      
        for f in files: 
            apkPath = os.path.join(root,f)
            target_file = csdConf.record_global_dir +  apkPath[apkPath.rfind("/"): ] + ".txt"
            def handler(signum, frame):
                print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec ]\n"
                with open(target_file, "a") as f:
                    f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                raise AssertionError   
            
            try:
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(csdConf.time_out)
                
                start = time.clock()
                
                print "=====================================\n"
                print "[START] "+ apkPath +"\n"
                print "=====================================\n"
                
                apk,d,inputDex = AnalyzeAPK(apkPath)
                
                mid = time.clock()
                
                with open(target_file, "a") as f:
                    f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                print "[time] Parse time is "+ str(mid-start) +"\n"
                
                csdGlobal.Main_Global((apk,d,inputDex),apkPath)
                
                end = time.clock()
                with open(target_file, "a") as f:
                    f.write("[time] Main_Global time is "+ str(end - mid) +"\n")
                    f.write("[time] Total time is "+ str(end - start) +"\n")
                    
                print "[time] Main_Global time is "+ str(end - mid) +"\n"
                print "[time] Total time is "+ str(end - start) +"\n"
                                    
                signal.alarm(0)   
                
                #apk,d,inputDex = AnalyzeAPK(apkPath)
                #csdGlobal.Main_Global((apk,d,inputDex), apkPath) 
            except Exception, e:                
                with open(target_file, "a") as f:
                    f.write("[ERROR]: app:"+ apkPath +"\n")
                    f.write(traceback.format_exc() +"\n")   
                    
                print "[ERROR]: app:"+ str(apkPath) +"\n"
                traceback.print_exc() 
            
                
    
def run_command(argv):
    
    
    try:
        # retrieve the arguments
        
        if (len(argv) == 0):
            print('Arguments number must not be 0, please try again.')
            usage()
            return        
        opts, args = getopt.getopt(argv, 'hp:s:c:g:', ['help', 'path=', 'service=','collect=','global='])
        #for a in argv:
            #print "args: " +a +"\n"
            
        #print str(len(opts))

    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    compile_option = None
    run_option = None

    for o, a in opts:
        #print "o: "+ o + "  a: " + a+"\n"
        if o in ('-h', "--help"):
            #print "i am help \n"
            usage()
            sys.exit()

        elif o in ('-p', '--path'):
            gen_option = a
            if gen_option == 'apk':
                if o=='-p':
                    apkPath = argv[2]   
                else: apkPath = argv[1]  
                target_p_file = csdConf.record_methodtrace_dir +  apkPath[apkPath.rfind("/"):] + ".txt"
                
                def handler(signum, frame):
                    print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n"
                    with open(target_p_file, "a") as f:
                        f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                    raise AssertionError                    
                try:
                    #timeout-machanism
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(csdConf.time_out)
                    
                    start = time.clock()
                    
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    
                    mid = time.clock()
                                        
                    with open(target_p_file, "a") as f:
                        f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                    print "[time] Parse time is "+ str(mid-start) +"\n"    
                    
                    csdAnalysis.Main_BackTrace_Source((apk,d,inputDex))
                    
                    end = time.clock()
                    with open(target_p_file, "a") as f:
                        f.write("[time] Method_trace time is "+ str(end - mid) +"\n")
                        f.write("[time] Total time is "+ str(end - start) +"\n")
                    print "[time] Method_trace time is "+ str(end - mid) +"\n"
                    print "[time] Total time is "+ str(end - start) +"\n"
                    
                    signal.alarm(0)                    
                except Exception, e:
                    with open(target_p_file, "a") as f:
                        f.write("[ERROR]: app:"+ apkPath +"\n")
                        f.write(traceback.format_exc() +"\n")
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                     
                
            #elif gen_option == 'dex':
                #if o=='-p':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]                
                #csdAnalysis.Main_BackTrace_Source(dexPath, "dex")  
            elif gen_option == 'dir':
                if o=='-p':
                    dirPath = argv[2]   
                else: dirPath = argv[1]                
                pathfromsourcetosink_dir(dirPath)             

        elif o in ('-s', '--service'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-s':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                target_k_file = csdConf.record_keycomponenttrace_dir +  apkPath[apkPath.rfind("/"):]+".txt"        
                def handler(signum, frame):
                    print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n"
                    with open(target_k_file, "a") as f:
                        f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                    raise AssertionError                   
                #csdAnalysis.Timeout_Main_If_Servicewithsink(apkPath, "apk")
                try:
                    #timeout-machanism
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(csdConf.time_out)
                    
                    start = time.clock()  
                    
                    print "===========================================\n"
                    print "[start] "+ str(apkPath) +"\n"
                    print "===========================================\n"
                    
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    
                    mid = time.clock()
                                        
                    with open(target_k_file, "a") as f:
                        f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                    print "[time] Parse time is "+ str(mid-start) +"\n"  
                                        
                    c, ret = csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex),csdConf.first_state_class, True)
                    
                    
                    end = time.clock()
                    with open(target_k_file, "a") as f:
                        f.write("[time] Main_If_Servicewithsink time is "+ str(end - mid) +"\n")
                        f.write("[time] Total time is "+ str(end - start) +"\n")                        
                        f.write("====================================================")
                        #f.write("[apk_package] "+ str(ret[0]) +"\n")
                        #f.write("[sink_dict] "+ str(ret[1])+"\n")
                        #f.write("[key_component] "+ str(ret[3])+"\n")
                        #f.write("[method_path]: \n")
                        #if ret[2]!= None and len(ret[2])>0:
                            #for method in ret[2]:
                                #f.write("  [method] "+ method.get_name()+" --> ")
                        for ret_elem in ret :
                            # ret_elem[0] == apk.get_package()
                            # ret_elem[1] == sink_dict
                            # ret_elem[2] == method_path
                            # ret_elem[3] == key_component                            
                            f.write("--[service_find_sink] (sink:"+ str(c.Sink2sinkstring(ret_elem[1])) +") \n")
                            f.write("----[method_path]: ") 
                            for m in ret_elem[2]:
                                f.write("(m)"+ m.get_name()+", " )                        
                        
                    print "[time] Main_If_Servicewithsink time is "+ str(end - mid) +"\n"
                    print "[time] Total time is "+ str(end - start) +"\n"
                    print "===================================================="
                     
                    signal.alarm(0)                    
                except Exception, e:
                    with open(target_k_file, "a") as f:
                        f.write("[ERROR]: app:"+ apkPath +"\n")
                        f.write(traceback.format_exc() +"\n")
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()               
                
            #elif gen_option == 'dex':
                #if o=='-s':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]             
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(dexPath, "dex")
                #csdAnalysis.Main_If_Servicewithsink(dexPath, "dex")
            elif gen_option == 'dir':
                if o=='-s':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                servicewithsink_dir(dirPath)  
                
        elif o in ('-c', '--collect'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-c':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                target_c_file = csdConf.record_collect_dir +  apkPath[apkPath.rfind("/"):]+".txt"               
                def handler(signum, frame):
                    print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n"
                    with open(target_c_file, "a") as f:
                        f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                    raise AssertionError                   
                #csdAnalysis.Timeout_Main_If_Servicewithsink(apkPath, "apk")
                try:
                    #timeout-machanism
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(csdConf.time_out)
                    
                    start = time.clock()   
                    
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    
                    mid = time.clock()
                                        
                    with open(target_c_file, "a") as f:
                        f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                    print "[time] Parse time is "+ str(mid-start) +"\n" 
                    
                    csdBlock, ret_total_collect = csdBlockAnalysis.Main_Collect((apk,d,inputDex))
                    
                    end = time.clock()
                    with open(target_c_file, "a") as f:
                        f.write("[time] Main_Collect time is "+ str(end - mid) +"\n")
                        f.write("[time] Total time is "+ str(end - start) +"\n")
                        f.write("===================================================")
                        
                    if ret_total_collect["total_collect_set"]!=None and\
                       len(ret_total_collect["total_collect_set"])>0:
                        for item in ret_total_collect["total_collect_set"]:
                                csdCollectionAnalysis.record_collect_set(ret_total_collect["total_collect_set"][item],
                                                            target_c_file)
                    
                    print "[time] Main_Collect time is "+ str(end - mid) +"\n"
                    print "[time] Total time is "+ str(end - start) +"\n"
                                        
                    signal.alarm(0)                    
                except Exception, e:
                    with open(target_c_file, "a") as f:
                        f.write("[ERROR]: app:"+ apkPath +"\n")
                        f.write(traceback.format_exc() +"\n")
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                      
                
            #elif gen_option == 'dex':
                #if o=='-c':
                    #dexPath = argv[2]   
                #else: dexPath = argv[1]             
                ##csdAnalysis.Timeout_Main_If_Servicewithsink(dexPath, "dex")
                #csdBlockAnalysis.Main_Collect(dexPath, "dex")    
                
            elif gen_option == 'dir':
                if o=='-c':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                collectconditionblock_dir(dirPath)  
                    
        elif o in ('-g', '--global'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-g':
                    apkPath = argv[2]   
                else: apkPath = argv[1]                 
                target_g_file = csdConf.record_global_dir +  apkPath[apkPath.rfind("/"):]+".txt"  
                
                def handler(signum, frame):
                    print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n"
                    with open(target_g_file, "a") as f:
                        f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(csdConf.time_out)+" sec]\n")
                    raise AssertionError                
                try:
                    
                    #timeout-machanism
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(csdConf.time_out)
                    
                    start = time.clock()
                    apk,d,inputDex = AnalyzeAPK(apkPath)
                    
                    mid = time.clock()
                    
                    with open(target_g_file, "a") as f:
                        f.write("[time] Parse time is "+ str(mid-start) +"\n")                   
                    print "[time] Parse time is "+ str(mid-start) +"\n"
                    
                    csdGlobal.Main_Global((apk,d,inputDex),apkPath)
                    
                    end = time.clock()
                    with open(target_g_file, "a") as f:
                        f.write("[time] Main_Global time is "+ str(end - mid) +"\n")
                        f.write("[time] Total time is "+ str(end - start) +"\n")
                        
                    print "[time] Main_Global time is "+ str(end - mid) +"\n"
                    print "[time] Total time is "+ str(end - start) +"\n"
                    
                    signal.alarm(0)
                    
                except Exception, e:
                    with open(target_g_file, "a") as f:
                        f.write("[ERROR]: app:"+ apkPath +"\n")
                        f.write(traceback.format_exc() +"\n")
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()                     
                                   
            elif gen_option == 'dir':
                if o=='-g':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                globalvuls_dir(dirPath)         

        else:
            print ("unknown option")
            sys.exit(2)
            
def usage():
    """ show usage of the commands"""
    print ("""
                -h, --help               show this help
                -p, --path               path from source to sink
                                        1. '-p apk': input type is .apk.
                                        2. '-p dir': input type is a directory.
                                        
                -s, --service            verify if existing service with sink 
                                        1. '-s apk': input type is .apk.
                                        2. '-s dir': input type is a directory.
                                        
                -c, --collect            collect the condition block of a given method_trace
                                        1. '-c apk': input type is .apk.
                                        2. '-c dir': input type is a directory.
                
                -g, --global             global observed activities analysis
                                        1. '-g apk': input type is .apk.
                                        2. '-g dir': input type is a directory.
                
    """)


if __name__ == '__main__':
    #cf.read(droidpf_home + '/conf/droidpf.conf')
    #setup()
    #RunIt().cmdloop()
    run_command(sys.argv[1:])
    #servicewithsink_dir("fsadfa.apk")
    

