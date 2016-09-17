# Motivating Example of AndroChecker

#### Source code
```java
public class ShareMyPosition extends MapActivity implements LocationListener {

private LocationManager locationManager;

public void onCreate(Bundle savedInstanceState)
{ ...locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE); ...}

private void performLocation(boolean forceNetwork)
    {...List<String> providers = locationManager.getProviders(true);   ...
            boolean containsGPS = providers.contains(LocationManager.GPS_PROVIDER);
            boolean containsNetwork = providers.contains(LocationManager.NETWORK_PROVIDER);
            if ((containsGPS && !forceNetwork) || (containsGPS && !containsNetwork)) {
                locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 5, this);
               }  else {...finish();}}       

protected void onResume()
{...   performLocation(false); }

protected void onPause()
{...   locationManager.removeUpdates(this); }

protected Dialog onCreateDialog(int id){
			return new AlertDialog.Builder(this).setTitle(R.string.app_name)
                    .setView(sharedMapView)
			.setNeutralButton(R.string.options, new OnClickListener() {
                        public void onClick(..., ...)
                        {...startActivity(option);} })
                    .setPositiveButton(R.string.share_it, new OnClickListener() {
                        public void onClick(..., ...)
			    {...startActivity(share);} })
			.setNegativeButton(R.string.retry, new OnClickListener() {
                        public void onClick(DialogInterface arg0, int arg1)
                        {...performLocation(false);}
                    }).create()}

public void onLocationChanged(final Location location)
    {...locationManager.removeUpdates(this);
        this.location = location;...}}
```





Description:

*Motivating example represents partial source code of app ShareMyPosition, which is used to share one's location to others. The main activity ShareMyPosition contains three lifecycle callbacks (onCreate (line 4, 5), onResume (line 15, 16) and onPause (line 18, 19)), as well as a system-driven callback (onLocationChanged (line 34-36). The main activity implements a listener interface LocationListener by overriding its method onLocationChanged. In the onCreate callback, ShareMyPosition defines and assigns a LocationManager variable locationManager. Then in the onResume, the locationManager variable is used to register the callback listener this via a self-defined method performLocation. 
Rather than registering it directly, the performLocation first judges whether one of the conditions containsGPS \&\& !forceNetwork and containsGPS \&\& !containsNetwork is satisfied (line 11). If so, the this object is registered as listener; otherwise, the lifecycle finishes. The system-driven callback onLocationChanged is activated along with the register action, but inactivated after the this listener is unregistered in the onPause or onLocationChanged callback. Besides of the system-driven callback, there exists three GUI callbacks in function onCreateDialog (line 21-32). These callbacks will be invoked when certain button-clicked event fires. Especially the event on PositiveButton (line 27-29) and NeutralButton (line 24-26) will trigger a new activity.*

 
Challenges:
* system-driven callback onLocationChanged is not directly invoked in the holder callback onResume. Instead, whether it is invoked is determined by the calculation of several condition variables (containsGPS, forceNetwork, etc.). One can simply ignore these condition variables and assume that all the invoker can be connected with the invokee callbacks, but this would result in significant confusion in traversing the callback flow model. To this end, a path-insensitive control flow impacts the precision of generated model. 

* lifecycle callbacks emerging in the example includes not only onCreate, but also
onResume and onPause. Traditional modelling manners handle the lifecycle callbacks in a coarse-grained way that only start (i.e. onCreate) and end (i.e. onDestroy) nodes are taken into consideration. Although it appears to be easy to handle the sequences of fine-grained callbacks like onResume and onPause among lifecycle callbacks, the modelling faces jumping confusion once non-lifecycle callbacks are involved. In our example, the onClick in line 28 takes a connection to start the activity share which can be denoted as PositiveButton.onClick -> share.onCreate. In theory, the onPause is known to be invoked when current activity loses its focus, so that it should be invoked before share.onCreate. Thus the path PositiveButton.onClick -> ShareMyPosition.onPause -> share.onCreate is supposed to be created. However, the ShareMyPosition.onPause -> share.onCreate becomes invalid when other paths pass. A typical invalid path is NeutralButton.onClick -> ShareMyPosition.onPause -> share.onCreate. Cases as the example make jumping action between activities confused. Apart from jumping confusion, the fine-grained hybrid model would result in other unexpected conflicts between lifecycle and non-lifecycle callbacks. Assuming that an onClick callback is registered in the onCreate, there should be an edge connecting the two callbacks. However, this edge would become invalid when encountering onResume, since the onResume should always be first invoked after the onCreate.

* Another challenge in the CCFG construction is the representation of inter-components, which is not explicit presented in the motivation example. As mentioned in Section \ref{background, the objective component in the inter-components jumping can be either service or activity. The jumping for activity can be treated as normal control flow since the invoker and invokee occur one after another. For the service, however, the jumping just acts as a launcher for triggering the objective component. There is not a strict time sequence between invoker and invokee in service case, because service runs in a parallel way with other components. A fine-grained modelling has to distinguish the two types of jumping.





### References:

 * [CCFG](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.709.8223&rep=rep1&type=pdf) 

