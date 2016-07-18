import os

def groupRunning():
    directory = "/home/guochenkai/download/SW/clawer_googleplay/clawerReal"
    
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs:
        for f in files:
            apkPath = os.path.join(root,f)
            os.popen("python  /home/guochenkai/download/SW/androguard/androguard/csdCmd.py -s apk " + str(apkPath))
            
if __name__ == '__main__':
    groupRunning()
    