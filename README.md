# 什么是 Activity 劫持
Android 为了提高用户的用户体验，对于不同的应用程序之间的切换，基本上是无缝。举一个例子，用户打开安卓手机上的某一应用例如支付宝，进入到登陆页面，这时恶意软件检测到用户的这一动作，立即弹出一个与支付宝界面相同的 Activity，覆盖掉了合法的 Activity，用户几乎无法察觉，该用户接下来输入用户名和密码的操作其实是在恶意软件的 Activity上进行的，接下来会发生什么就可想而知了。具体关于 Activity 劫持原理可以参考如下这篇文章：https://blog.csdn.net/nailsoul/article/details/11767243

**[阿里聚安全](https://jaq.alibaba.com/index)**
阿里聚安全旗下产品安全组件 SDK 具有安全签名、安全加密、安全存储、模拟器检测、反调试、反注入、反 Activity 劫持等功能。 开发者只需要简单集成安全组件 SDK 就可以有效解决上述登录窗口被木马病毒劫持的问题，从而帮助用户和企业减少损失。

# 防护手段

目前，还没有什么专门针对 Activity 劫持的防护方法，因为，这种攻击是用户层面上的，目前还无法从代码层面上根除。但是，我们可以适当地在 APP 中给用户一些警示信息，提示用户其登陆界面以被覆盖。在网上查了很多解决方法如下：
- 在 Acitivity 的 onStop 方法中 调用封装的 AntiHijackingUtil 类（检测系统程序白名单）检测程序是否被系统程序覆盖。
- 在前面建立的正常Activity的登陆界面（也就是 MainActivity）中重写 onKeyDown 方法和 onPause 方法，判断程序进入后台是否是用户自身造成的（触摸返回键或 HOME 键）这样一来，当其被覆盖时，就能够弹出警示信息。

AntiHijackingUtil 类代码如下：
```
public class AntiHijackingUtil {

    public static final String TAG = "AntiHijackingUtil";

    // 白名单列表
    private static List<String> safePackages;

    static {
        safePackages = new ArrayList<String>();
    }

    public static void configSafePackages(List<String> packages) {
        return;
    }
    private static PackageManager pm;
    private List<ApplicationInfo> mlistAppInfo;
    /**
     * 检测当前Activity是否安全
     */
    public static boolean checkActivity(Context context) {
         boolean safe = false;
         pm = context.getPackageManager();
            // 查询所有已经安装的应用程序
            List<ApplicationInfo> listAppcations = pm.getInstalledApplications(PackageManager.GET_UNINSTALLED_PACKAGES);
            Collections.sort(listAppcations,new ApplicationInfo.DisplayNameComparator(pm));// 排序
            List<ApplicationInfo> appInfos = new ArrayList<ApplicationInfo>(); // 保存过滤查到的AppInfo
            //appInfos.clear();
         for (ApplicationInfo app : listAppcations) {//这个排序必须有.
             if ((app.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                 //appInfos.add(getAppInfo(app));
                safePackages.add(app.packageName);
             }
         }
         //得到所有的系统程序包名放进白名单里面.

        ActivityManager activityManager =(ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        String runningActivityPackageName;
        int sdkVersion;

        try {
            sdkVersion = Integer.valueOf(android.os.Build.VERSION.SDK);
        } catch (NumberFormatException e) {
            sdkVersion = 0;
        }

        if(sdkVersion>=21){//获取系统api版本号,如果是5x系统就用这个方法获取当前运行的包名
            runningActivityPackageName= getCurrentPkgName(context);
        }
        else runningActivityPackageName=activityManager.getRunningTasks(1).get(0).topActivity.getPackageName();
        //如果是4x及以下,用这个方法.


        if(runningActivityPackageName!=null){//有些情况下在5x的手机中可能获取不到当前运行的包名，所以要非空判断。
           if (runningActivityPackageName.equals(context.getPackageName())) {
              safe = true;
           }

            // 白名单比对
           for (String safePack : safePackages) {
               if (safePack.equals(runningActivityPackageName)) {
                   safe = true;
               }
           }
        }

        return safe;
    }



    public static String getCurrentPkgName(Context context) {//5x系统以后利用反射获取当前栈顶activity的包名.
        ActivityManager.RunningAppProcessInfo currentInfo = null;
        Field field = null;
        int START_TASK_TO_FRONT = 2;
        String pkgName = null;

        try {
            field = ActivityManager.RunningAppProcessInfo.class.getDeclaredField("processState");//通过反射获取进程状态字段.
        } catch (Exception e) {
            e.printStackTrace();
        }
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List appList = am.getRunningAppProcesses();
        ActivityManager.RunningAppProcessInfo app;

        for (int i=0;i<appList.size();i++){
            //ActivityManager.RunningAppProcessInfo app : appList
            app=(RunningAppProcessInfo) appList.get(i);
            if (app.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {//表示前台运行进程.
                Integer state = null;
                try {
                    state = field.getInt(app);//反射调用字段值的方法,获取该进程的状态.
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (state != null && state == START_TASK_TO_FRONT) {//根据这个判断条件从前台中获取当前切换的进程对象.
                    currentInfo = app;
                    break;
                }
            }
        }

        if (currentInfo != null) {
            pkgName = currentInfo.processName;
        }
        return pkgName;
    }
}
```
重写 onKeyDown 方法和 onPause 方法
```
 @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        //判断程序进入后台是否是用户自身造成的（触摸返回键或HOME键），是则无需弹出警示。
        if ((keyCode == KeyEvent.KEYCODE_BACK || keyCode == KeyEvent.KEYCODE_HOME) && event.getRepeatCount() == 0) {
            needAlarm = false;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    protected void onPause() {
        Log.d("LoginActivity", "是否需要提醒：" + needAlarm);
        // 若程序进入后台不是用户自身造成的，则需要弹出警示
        if (needAlarm) {
            //弹出警示信息
            Toast.makeText(getApplicationContext(),
                    R.string.activity_safe_warning, Toast.LENGTH_SHORT).show();
        }
        super.onPause();
    }
```

**但是这两种方法都存在问题，Android onKeyDown 方法目前根本无法监听到 HOME 键，你们可以用代码试一下，我这边验证过了。AntiHijackingUtil 类只检测了系统程序，发现在锁屏状态下代码无法检查也提示警告。效果如下在点击 HOME 键和锁屏在解锁的情况下依然提示应用警告。**
![Activity 劫持防护失败](https://upload-images.jianshu.io/upload_images/2515909-e172ef5cdeace028.gif?imageMogr2/auto-orient/strip)
## 防护方法改进
Activity 劫持防护我们想达到的预期目标如下：
- 用户主动退出 APP ( 返回键 、HOME 键)这种情况下我们不需要给用户弹出警告提示
- APP 在锁屏再解锁的情况下我们不需要给用户弹出警告提示
- 其他应用突然覆盖在我们 APP 上时给出合理的警告提示

## APP 返回桌面、锁屏再解锁情况检测代码
```
 /**
     * 判断当前是否在桌面
     *
     * @param context 上下文
     */
    public static boolean isHome(Context context) {
        ActivityManager mActivityManager =
                (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningTaskInfo> rti = mActivityManager.getRunningTasks(1);
        return getHomes(context).contains(rti.get(0).topActivity.getPackageName());
    }

    /**
     * 获得属于桌面的应用的应用包名称
     *
     * @return 返回包含所有包名的字符串列表
     */
    private static List<String> getHomes(Context context) {
        List<String> names = new ArrayList<String>();
        PackageManager packageManager = context.getPackageManager();
        Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.addCategory(Intent.CATEGORY_HOME);
        List<ResolveInfo> resolveInfo = packageManager.queryIntentActivities(intent,
                PackageManager.MATCH_DEFAULT_ONLY);
        for (ResolveInfo ri : resolveInfo) {
            names.add(ri.activityInfo.packageName);
        }
        return names;
    }

    /**
     * 判断当前是否在锁屏再解锁状态
     *
     * @param context 上下文
     */
    public static boolean isReflectScreen(Context context) {
        KeyguardManager mKeyguardManager =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return mKeyguardManager.inKeyguardRestrictedInputMode();
    }
```
并且在 onStop 方法中检测是否需要弹出警告提醒
```
    @Override
    protected void onStop() {
        super.onStop();
        // 白名单
        boolean safe = AntiHijackingUtil.checkActivity(this);
        // 系统桌面
        boolean isHome = AntiHijackingUtil.isHome(this);
        // 锁屏操作
        boolean isReflectScreen = AntiHijackingUtil.isReflectScreen(this);
        // 判断程序是否当前显示
        if (!safe && !isHome && !isReflectScreen) {
            Toast.makeText(getApplicationContext(), R.string.activity_safe_warning,
                    Toast.LENGTH_LONG).show();
        }
    }
```
感觉问题解决了，我们通过点击通知栏打开其他应用来模拟恶意软件覆盖咱们的 APP来看一下应用运行效果吧
![Activity 劫持防护成功](https://upload-images.jianshu.io/upload_images/2515909-ffe6fca639702d0d.gif?imageMogr2/auto-orient/strip)
