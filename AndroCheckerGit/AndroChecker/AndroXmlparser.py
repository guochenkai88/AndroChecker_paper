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

#import csdConf
import copy 

import AndroConf

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
    
class AndroXmlparser(object):
    def __init__(self, xml_file) :        
         
        self.tree = ET.ElementTree(file = xml_file)
        
        
        
    def get_response_functions(self):        
        ret = []
        for v in AndroConf.xml_viewnodes:
            for elem in self.tree.iter(tag=v):
                for key in elem.attrib:
                    for i in AndroConf.xml_viewnodes[v]:
                        if key.find(i)>-1:
                            ret.append((v + ":"+ i, elem.attrib[key]))
        return ret
    
if __name__ == "__main__":
    xml_file = "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/test/test1.xml"
    a = AndroXmlparser(xml_file)
    
    ret = a.get_response_functions()
    
    print ret
                
    