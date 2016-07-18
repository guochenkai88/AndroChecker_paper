
ABTRARY = "abitrary"
SEPARATOR = "/"

model_file = "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/models/result_model5.smv"

xml_viewnodes = {
    "Button":["onClick"]
    #"TextView": ["onClick"]
    }

register_vectors = (
    {"register":"addGpsStatusListener", "class":"Landroid/location/LocationManager", "para":"GpsStatus$Listener", "key_para":"GpsStatus$Listener"},
    #{"register":"addGpsStatusListener", "class":"Landroid/location/LocationManager", "para":"GpsStatus/Listener", "key_para":"GpsStatus/Listener"}
    {"register":"requestLocationUpdates", "class":"Landroid/location/LocationManager", "para":"Ljava/lang/String; J F Landroid/location/LocationListener", "key_para":"Landroid/location/LocationListener"},
    {"register":"registerListener", "class":"", "para":"", "key_para":""},
    {"register":"registerComponentCallbacks", "class":"Landroid/content/Context", "para":"Landroid/content/ComponentCallbacks", "key_para":"Landroid/content/ComponentCallbacks"},
    {"register":"registerReceiver", "class":"Landroid/content/Context", "para":"Landroid/content/BroadcastReceiver  Landroid/content/IntentFilter", "key_para":"Landroid/content/BroadcastReceiver"},
    #{"register":"registerReceiver", "class":"Landroid/content/Context", "para":"Landroid/content/BroadcastReceiver  Landroid/content/IntentFilter Ljava/lang/String; Landroid/os/Handler", "key_para":"Landroid/content/BroadcastReceiver"},
    {"register":"setOnClickListener", "class":"Landroid/widget/Button", "para":"Landroid/view/View$OnClickListener", "key_para":"Landroid/view/View$OnClickListener"},  
    {"register":"setOnTouchListener", "class":"", "para":"", "key_para":""},
    {"register":"setOnGenericMotionListener", "class":"", "para":"", "key_para":""},
    {"register":"setOnLongClickListener", "class":"", "para":"", "key_para":""},
    {"register":"setOnDragListener", "class":"", "para":"", "key_para":""},
    {"register":"setOnFocusChangeListener", "class":"", "para":"", "key_para":""},
    {"register":"setOnCreateContextMenuListener", "class":"", "para":"", "key_para":""},
)
unregister_vectors =(
    {"register":"unregisterComponentCallbacks", "class":"Landroid/content/Context", "para":"Landroid/content/ComponentCallbacks", "key_para":"Landroid/content/ComponentCallbacks"},
    {"register":"unregisterReceiver", "class":"Landroid/content/Context", "para":"Landroid/content/BroadcastReceiver", "key_para":"Landroid/content/BroadcastReceiver"},
    {"register":"removeUpdates", "class":"Landroid/location/LocationManager", "para":"GpsStatus$Listener", "key_para":"GpsStatus$Listener"},
    {"register":"unregisterListener", "class":"", "para":"", "key_para":""}

)

connection_vectors = (
    {"connection":"startActivity", "class":"Landroid/content/Context", "para":"Landroid/content/Intent", "key_para":"Landroid/content/Intent"},
    #{"connection":"startActivity", "class":"Landroid/content/Context", "para":"Landroid/content/Intent Landroid/os/Bundle", "key_para":"Landroid/content/Intent"},
    {"connection":"startService", "class":"Landroid/content/Context", "para":"Landroid/content/Intent", "key_para":"Landroid/content/Intent"},
    {"connection":"stopService", "class":"Landroid/content/Context", "para":"Landroid/content/Intent", "key_para":"Landroid/content/Intent"},
    {"connection":"bindService", "class":"Landroid/content/Context", "para":"Landroid/content/Intent Landroid/content/ServiceConnection I", "key_para":"Intent"},
    {"connection":"unbindService", "class":"Landroid/content/Context", "para":"Landroid/content/ServiceConnection", "key_para":"Landroid/content/ServiceConnection"},
    {"connection":"startActivities", "class":"Landroid/content/Context", "para":"Landroid/content/Intent", "key_para":"Landroid/content/Intent"},
)

lifecycle = ["<init>", "onCreate","onStart","onResume","onPause","onStop","onDestroy","onRestart",   "onStartCommand","onBind","onUnbind",    "onReceive"]

target = (
    #startActivity
    { "class": "android.content.Context", "method":"startActivity", "params":ABTRARY, "return":ABTRARY }, 
    
    #dialog
    { "class": "AlertDialog.Builder", "method":"create", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "DatePickerDialog.Builder", "method":"create", "params":ABTRARY, "return":ABTRARY },
    { "class": "TimePickerDialog.Builder", "method":"create", "params":ABTRARY, "return":ABTRARY },    
    
    #toast
    { "class": "android.widget.Toast", "method":"makeText", "params":ABTRARY, "return":ABTRARY }, 
    
)

callbacks = (
    #android.app.Activity
    { "class": "android.app.Activity", "method":"onCreateOprionsMenu", "params":ABTRARY, "return":ABTRARY },  
    { "class": "android.app.Activity", "method":"onKeyDown", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onOprionsItemSelected", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onPrepareOptionsMenu", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onActivityResult", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onConfigurationChanged", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onCreate", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onCreateContextMenu", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onDestroy", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onPause", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onRestart", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onResume", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onSaveInstanceState", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onStart", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onStop", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Activity", "method":"onWindowFocusChanged", "params":ABTRARY, "return":ABTRARY },
    
    #android.app.Dialog
    { "class": "android.app.Dialog", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Dialog", "method":"onCreate", "params":ABTRARY, "return":ABTRARY },
    
    #android.app.ListActivity
    { "class": "android.app.ListActivity", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.ListActivity", "method":"onCreate", "params":ABTRARY, "return":ABTRARY },  
    
    #android.app.Service
    { "class": "android.app.Service", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onCreate", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onDestroy", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onBind", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onLowMemory", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onStart", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.app.Service", "method":"onStartCommand", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.content.BroadcastReceiver
    { "class": "android.content.BroadcastReceiver", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.content.BroadcastReceiver", "method":"onReceive", "params":ABTRARY, "return":ABTRARY },  
    
    #android.content.ContentProvider
    { "class": "android.content.ContentProvider", "method":"<init>", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.content.ContentProvider", "method":"onCreate", "params":ABTRARY, "return":ABTRARY },   
    
    #android.content.ServiceConnection
    { "class": "android.content.ServiceConnection", "method":"onServiceConnected", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.content.ServiceConnection", "method":"onServiceDisconnected", "params":ABTRARY, "return":ABTRARY },      


    #android.os.AsyncTask
    { "class": "android.os.AsyncTask", "method":"doInBackground", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.os.AsyncTask", "method":"onPostExecute", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.os.AsyncTask", "method":"onPreExecute", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.os.Handler
    { "class": "android.os.Handler", "method":"handleMessage", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.preference.PreferenceActivity
    { "class": "android.preference.PreferenceActivity", "method":"onPreferenceTreeClick", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.preference.PreferenceActivity", "method":"<init>", "params":ABTRARY, "return":ABTRARY },  
    { "class": "android.preference.PreferenceActivity", "method":"onCreate", "params":ABTRARY, "return":ABTRARY },
    { "class": "android.preference.PreferenceActivity", "method":"onDestroy", "params":ABTRARY, "return":ABTRARY },
    { "class": "android.preference.PreferenceActivity", "method":"onStop", "params":ABTRARY, "return":ABTRARY },
    
    #android.preference.Preference.OnPreferenceChangeListener
    { "class": "android.preference.Preference.OnPreferenceChangeListener", "method":"onPreferenceChange", "params":ABTRARY, "return":ABTRARY },    
    
    #android.preference.Preference.OnPreferenceClickListener
    { "class": "android.preference.Preference.OnPreferenceClickListener", "method":"onPreferenceClick", "params":ABTRARY, "return":ABTRARY },  
    
    #android.telephony.PhoneStateListener
    { "class": "android.telephony.PhoneStateListener", "method":"onCallStateChanged", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.view.View.OnClickListener
    { "class": "android.view.View.OnClickListener", "method":"onClick", "params":ABTRARY, "return":ABTRARY },
    
    #android.view.View.OnTouchListener
    { "class": "android.view.View.OnTouchListener", "method":"onTouch", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.webkit.WebChromeClient
    { "class": "android.webkit.WebChromeClient", "method":"onProgressChanged", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.webkit.WebViewClient
    { "class": "android.webkit.WebViewClient", "method":"onPageFinished", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.webkit.WebViewClient", "method":"onPageStarted", "params":ABTRARY, "return":ABTRARY }, 
    { "class": "android.webkit.WebViewClient", "method":"onReceivedError", "params":ABTRARY, "return":ABTRARY }, 

    #android.widget.AdapterView.OnItemClickListener
    { "class": "android.widget.AdapterView.OnItemClickListener", "method":"onItemClick", "params":ABTRARY, "return":ABTRARY }, 
    
    #android.widget.AdapterView.OnItemLongClickListener
    { "class": "android.widget.AdapterView.OnItemLongClickListener", "method":"onItemLongClick", "params":ABTRARY, "return":ABTRARY },
    
    #java.lang.Runnable
    { "class": "java.lang.Runnable", "method":"run", "params":ABTRARY, "return":ABTRARY },
    
    #java.lang.Thread
    { "class": "java.lang.Thread", "method":"run", "params":ABTRARY, "return":ABTRARY },
)

whitelist = (
    {
        "package":"Lcom/google/ads",
        "class":ABTRARY,
        "method":ABTRARY,
        "params":ABTRARY,
        "return":ABTRARY
        
    },
    {
        "package":"Landroid/support/v4",
        "class":ABTRARY,
        "method":ABTRARY,
        "params":ABTRARY,
        "return":ABTRARY
    },
    {
        "package":"Lbucik/gps/satellite/signal/checker",
        "class":"Gps8Activity$MyLocationListener;",
        "method":"onLocationChanged",
        "params":"Landroid/location/Location; I",
        "return":"V"
    },     
)