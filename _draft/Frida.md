Frida

List all applications
frida-ps -Uai

Hook app
frida -U "APP"

Hook a function of a class (with * hook all functions)
frida-trace -U "APP" -m "-[CLASS FUNCTION]"

Hook nsurl
frida-trace -U "APP" -m "-[NSULR *]"

Hook native functions
"*URL*"
frida-trace -U "APP" -i "open*"

# Trace recv* and send* APIs in Safari
$ frida-trace -i "recv*" -i "send*" Safari

# Trace ObjC method calls in Safari
$ frida-trace -m "-[NSView drawRect:]" Safari

# Launch SnapChat on your iPhone and trace crypto API calls
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"


https://hacking-etico.com/2017/11/09/ios-hacking-introduccion-al-analisis-dinamico-aplicaciones-frida/
https://blog.attify.com/bypass-jailbreak-detection-frida-ios-applications/
https://www.nowsecure.com/blog/2017/04/27/owasp-ios-crackme-tutorial-frida/


w = ObjC.classes.UIWindow.keyWindow()
desc = w.recursiveDescription().toString()
$ frida -q -U UnCrackable1 -e "ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();" |grep "UILabel.*hidden.*"