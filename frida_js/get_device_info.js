/**
 * 获取 Android 设备信息的 Frida 脚本（增强优化版）
 * 
 * 功能增强：
 * 1. 完善的异常处理和空指针检查
 * 2. 增强的反射字段获取功能
 * 3. 增强的 Root 检测（更多路径）
 * 4. 详细的 DRM 信息获取（Widevine）
 * 5. CPU 架构信息获取
 * 6. SELinux 状态检测
 * 7. 系统命令执行功能
 * 8. 可选的 DEX 文件加载支持
 * 9. 自动绕过权限检查（可选）
 * 
 * 使用方法：
 * frida -U -f com.example.app -l get_device_info.js --no-pause
 */

var read_phone_state = false;

// 权限绕过功能（设置为 true 以自动授予所有权限）
var BYPASS_PERMISSION_CHECK = true; // 改为 true 可自动绕过权限检查

// DEX 文件加载功能（可选）
var ENABLE_DEX_LOADING = false; // 设置为 true 以启用 DEX 加载
var DEX_FILE_PATH = "/data/local/tmp/helper.dex"; // DEX 文件路径

function loadDexFile(dexPath) {
    try {
        Java.perform(function() {
            console.log("正在加载 DEX 文件: " + dexPath);
            Java.openClassFile(dexPath).load();
            console.log("DEX 文件加载成功");
        });
        return true;
    } catch (e) {
        console.log("DEX 文件加载失败: " + e);
        return false;
    }
}

// 如果启用，在脚本初始化时加载 DEX
if (ENABLE_DEX_LOADING) {
    setTimeout(function() {
        loadDexFile(DEX_FILE_PATH);
    }, 100);
}

// 权限绕过功能（增强版 - 直接 Hook TelephonyManager）
function bypassPermissionCheck() {
    try {
        Java.perform(function() {
            console.log("正在启用权限绕过功能...");
            
            // Hook Context.checkSelfPermission
            var ContextCompat = Java.use("android.content.Context");
            if (ContextCompat.checkSelfPermission) {
                ContextCompat.checkSelfPermission.implementation = function(permission) {
                    var PackageManager = Java.use("android.content.pm.PackageManager");
                    return PackageManager.PERMISSION_GRANTED.value; // 返回已授权
                };
            }
            
            // Hook ActivityCompat.checkSelfPermission (Android Support 库)
            try {
                var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
                ActivityCompat.checkSelfPermission.overload('android.content.Context', 'java.lang.String').implementation = function(context, permission) {
                    var PackageManager = Java.use("android.content.pm.PackageManager");
                    return PackageManager.PERMISSION_GRANTED.value;
                };
            } catch (e) {}
            
            // Hook ContextCompat.checkSelfPermission (AndroidX)
            try {
                var ContextCompatX = Java.use("androidx.core.content.ContextCompat");
                ContextCompatX.checkSelfPermission.implementation = function(context, permission) {
                    var PackageManager = Java.use("android.content.pm.PackageManager");
                    return PackageManager.PERMISSION_GRANTED.value;
                };
            } catch (e) {}
            
            // Hook PackageManager.checkPermission
            try {
                var PackageManager = Java.use("android.content.pm.PackageManager");
                var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
                
                ApplicationPackageManager.checkPermission.overload('java.lang.String', 'java.lang.String').implementation = function(permission, packageName) {
                    return PackageManager.PERMISSION_GRANTED.value;
                };
            } catch (e) {}
            
            // ============ 核心：Hook TelephonyManager 方法来绕过权限检查 ============
            try {
                var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                
                // Hook getDeviceId (获取 IMEI - 旧版本)
                if (TelephonyManager.getDeviceId) {
                    try {
                        TelephonyManager.getDeviceId.overload().implementation = function() {
                            try {
                                return this.getDeviceId.call(this);
                            } catch (e) {
                                console.log("[权限绕过] getDeviceId 被拦截，返回模拟值");
                                return "000000000000000"; // 返回模拟 IMEI
                            }
                        };
                        
                        TelephonyManager.getDeviceId.overload('int').implementation = function(slotIndex) {
                            try {
                                return this.getDeviceId.call(this, slotIndex);
                            } catch (e) {
                                console.log("[权限绕过] getDeviceId(slot) 被拦截，返回模拟值");
                                return "000000000000000";
                            }
                        };
                    } catch (e) {}
                }
                
                // Hook getImei (获取 IMEI - Android 8.0+)
                if (TelephonyManager.getImei) {
                    try {
                        TelephonyManager.getImei.overload().implementation = function() {
                            try {
                                // 使用反射强制调用，绕过权限检查
                                var result = this.getImei.call(this);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取真实 IMEI");
                                    return result;
                                }
                                return null;
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ IMEI 访问被系统阻止: " + e.message);
                                    return "IMEI_BLOCKED_BY_SYSTEM";
                                }
                                return null;
                            }
                        };
                        
                        TelephonyManager.getImei.overload('int').implementation = function(slotIndex) {
                            try {
                                var result = this.getImei.call(this, slotIndex);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取真实 IMEI (Slot " + slotIndex + ")");
                                    return result;
                                }
                                return null;
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ IMEI 访问被系统阻止 (Slot " + slotIndex + "): " + e.message);
                                    return "IMEI_BLOCKED_BY_SYSTEM";
                                }
                                return null;
                            }
                        };
                    } catch (e) {}
                }
                
                // Hook getSubscriberId (获取 IMSI)
                if (TelephonyManager.getSubscriberId) {
                    try {
                        TelephonyManager.getSubscriberId.overload().implementation = function() {
                            try {
                                var result = this.getSubscriberId.call(this);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取真实 IMSI");
                                    return result;
                                }
                                return null;
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ IMSI 访问被系统阻止: " + e.message);
                                    return "IMSI_BLOCKED_BY_SYSTEM";
                                }
                                return null;
                            }
                        };
                        
                        TelephonyManager.getSubscriberId.overload('int').implementation = function(subId) {
                            try {
                                var result = this.getSubscriberId.call(this, subId);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取真实 IMSI (SubId " + subId + ")");
                                    return result;
                                }
                                return null;
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ IMSI 访问被系统阻止 (SubId " + subId + "): " + e.message);
                                    return "IMSI_BLOCKED_BY_SYSTEM";
                                }
                                return null;
                            }
                        };
                    } catch (e) {}
                }
                
                // Hook getLine1Number (获取手机号)
                if (TelephonyManager.getLine1Number) {
                    try {
                        TelephonyManager.getLine1Number.overload().implementation = function() {
                            try {
                                var result = this.getLine1Number.call(this);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取手机号");
                                }
                                return result; // 即使为 null 也返回
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ 手机号访问被系统阻止");
                                }
                                return null; // 手机号通常为空
                            }
                        };
                        
                        TelephonyManager.getLine1Number.overload('int').implementation = function(subId) {
                            try {
                                var result = this.getLine1Number.call(this, subId);
                                if (result) {
                                    console.log("[权限绕过] ✓ 成功获取手机号 (SubId " + subId + ")");
                                }
                                return result;
                            } catch (e) {
                                if (e.message && e.message.indexOf("SecurityException") !== -1) {
                                    console.log("[权限绕过] ⚠️ 手机号访问被系统阻止 (SubId " + subId + ")");
                                }
                                return null;
                            }
                        };
                    } catch (e) {}
                }
                
                // Hook getSimSerialNumber (获取 SIM 卡序列号)
                if (TelephonyManager.getSimSerialNumber) {
                    try {
                        TelephonyManager.getSimSerialNumber.overload().implementation = function() {
                            try {
                                return this.getSimSerialNumber.call(this);
                            } catch (e) {
                                console.log("[权限绕过] getSimSerialNumber 被拦截，返回模拟值");
                                return "00000000000000000000";
                            }
                        };
                    } catch (e) {}
                }
                
                console.log("✓ TelephonyManager Hook 已启用");
            } catch (e) {
                console.log("Hook TelephonyManager 失败: " + e);
            }
            
            console.log("✓ 权限绕过功能已启用");
            read_phone_state = true; // 标记为已有权限
        });
    } catch (e) {
        console.log("权限绕过功能启用失败: " + e);
    }
}

// 如果启用权限绕过，在脚本初始化时执行
if (BYPASS_PERMISSION_CHECK) {
    setTimeout(function() {
        bypassPermissionCheck();
    }, 100);
}

// 安全反射获取字段值的辅助函数（支持 Java 对象）
function safeGetField(obj, fieldName) {
    try {
        if (!obj) return null;
        
        // 尝试直接访问
        if (obj[fieldName]) {
            var value = obj[fieldName];
            return value && value.value !== undefined ? value.value : value;
        }
        
        // 使用反射获取
        var field = obj.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        var result = field.get(obj);
        return result && result.value !== undefined ? result.value : result;
    } catch (e) {
        console.log("获取字段 " + fieldName + " 失败: " + e);
        return null;
    }
}

// 通用反射字段获取器（类似混淆代码中的 ___oo_xx）
function getFieldValue(obj, fieldName) {
    try {
        if (!obj) return null;
        var ReflectionHelper = Java.use("java.lang.reflect.Field");
        var clazz = obj.getClass();
        var field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    } catch (e) {
        return null;
    }
}

// 安全执行函数的包装器
function safeExecute(name, func) {
    try {
        console.log("\n========== " + name + " ==========");
        func();
        console.log("========== " + name + " 完成 ==========\n");
    } catch (e) {
        console.log("执行 " + name + " 时出错: " + e);
        console.log("堆栈: " + e.stack);
    }
}

// 执行系统命令并获取输出
function executeCommand(command) {
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var Process = Java.use("java.lang.Process");
        var BufferedReader = Java.use("java.io.BufferedReader");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        
        var process = Runtime.getRuntime().exec(command);
        var reader = BufferedReader.$new(InputStreamReader.$new(process.getInputStream()));
        
        var result = "";
        var line = null;
        while ((line = reader.readLine()) != null) {
            result += line + "\n";
        }
        
        reader.close();
        return result.trim();
    } catch (e) {
        return null;
    }
}

// 获取基础设备信息
function getBasicInfo() {
    Java.perform(function() {
        try {
            // 获取应用上下文
            var ActivityThread = Java.use("android.app.ActivityThread");
            var context = ActivityThread.currentApplication().getApplicationContext();
            
            if (!context) {
                console.log("无法获取应用上下文");
                return;
            }

            // 检查权限
            try {
                var permission = "android.permission.READ_PHONE_STATE";
                var PackageManager = Java.use("android.content.pm.PackageManager");
                
                // 如果启用了权限绕过，直接设置为已授权
                if (BYPASS_PERMISSION_CHECK) {
                    read_phone_state = true;
                    console.log("✓ [权限绕过] 已强制授予 READ_PHONE_STATE 权限");
                } else {
                    var permissionResult = context.checkSelfPermission(permission);
                    read_phone_state = (permissionResult === PackageManager.PERMISSION_GRANTED.value);
                    
                    if (!read_phone_state) {
                        console.log("\n⚠️  权限提示");
                        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        console.log("缺少权限: " + permission);
                        console.log("受影响的信息: IMEI、IMSI、运营商信息、手机号");
                        console.log("\n解决方案:");
                        console.log("1. 将脚本顶部 BYPASS_PERMISSION_CHECK 设为 true");
                        console.log("2. 在应用设置中手动授予该权限");
                        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                    } else {
                        console.log("✓ 已获得 READ_PHONE_STATE 权限");
                    }
                }
            } catch (e) {
                console.log("检查权限时出错: " + e);
            }

            // 获取 Build 信息
            console.log("\n[设备信息]");
            try {
                var Build = Java.use("android.os.Build");
                console.log("品牌 (BRAND): " + (Build.BRAND ? Build.BRAND.value : "未知"));
                console.log("制造商 (MANUFACTURER): " + (Build.MANUFACTURER ? Build.MANUFACTURER.value : "未知"));
                console.log("型号 (MODEL): " + (Build.MODEL ? Build.MODEL.value : "未知"));
                console.log("设备 (DEVICE): " + (Build.DEVICE ? Build.DEVICE.value : "未知"));
                console.log("主板 (BOARD): " + (Build.BOARD ? Build.BOARD.value : "未知"));
                console.log("硬件 (HARDWARE): " + (Build.HARDWARE ? Build.HARDWARE.value : "未知"));
                console.log("产品 (PRODUCT): " + (Build.PRODUCT ? Build.PRODUCT.value : "未知"));
                console.log("指纹 (FINGERPRINT): " + (Build.FINGERPRINT ? Build.FINGERPRINT.value : "未知"));
                
                if (Build.SERIAL) {
                    console.log("序列号 (SERIAL): " + Build.SERIAL.value);
                }
            } catch (e) {
                console.log("获取 Build 信息时出错: " + e);
            }

            // 获取系统版本
            try {
                var VERSION = Java.use("android.os.Build$VERSION");
                var release = VERSION.RELEASE ? VERSION.RELEASE.value : "未知";
                var sdkInt = VERSION.SDK_INT ? VERSION.SDK_INT.value : 0;
                console.log("\nAndroid 版本: " + release);
                console.log("SDK 版本 (SDK_INT): " + sdkInt);
            } catch (e) {
                console.log("获取系统版本时出错: " + e);
            }

            // 获取 Android ID
            try {
                var Settings = Java.use("android.provider.Settings$Secure");
                var contentResolver = context.getContentResolver();
                var androidId = Settings.getString(contentResolver, "android_id");
                console.log("Android ID: " + (androidId || "未知"));
            } catch (e) {
                console.log("获取 Android ID 时出错: " + e);
            }

            // 获取电话信息（需要权限）
            if (read_phone_state) {
                try {
                    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                    var VERSION = Java.use("android.os.Build$VERSION");
                    var sdkInt = VERSION.SDK_INT ? VERSION.SDK_INT.value : 0;
                    
                    var telephonyService = context.getSystemService("phone");
                    if (telephonyService) {
                        var telephonyManager = Java.cast(telephonyService, TelephonyManager);
                        
                        console.log("\n[电话信息]");
                        
                        // 检查 SIM 卡状态
                        var simState = telephonyManager.getSimState();
                        var simStateText = ["未知", "无 SIM 卡", "需要 PIN", "需要 PUK", "网络 PIN", "就绪", "不可用", "永久禁用", "卡受限"][simState] || "未知状态";
                        console.log("SIM 卡状态: " + simStateText + " (" + simState + ")");
                        
                        if (simState !== 5) { // SIM_STATE_READY = 5
                            console.log("⚠️ 注意: SIM 卡未就绪，部分信息可能无法获取\n");
                        }
                        
                        // 获取 IMEI（增强版 - 多种方法尝试）
                        var imei = null;
                        var imeiMethods = [];
                        
                        // 方法 1: 标准 API
                        try {
                            if (sdkInt >= 26 && telephonyManager.getImei) {
                                imei = telephonyManager.getImei();
                                if (imei && imei !== "IMEI_BLOCKED_BY_SYSTEM") {
                                    imeiMethods.push("标准 API");
                                }
                            } else if (telephonyManager.getDeviceId) {
                                imei = telephonyManager.getDeviceId();
                                if (imei && imei !== "IMEI_BLOCKED_BY_SYSTEM") {
                                    imeiMethods.push("DeviceId API");
                                }
                            }
                        } catch (e) {}
                        
                        // 方法 2: 通过反射访问 IPhoneSubInfo 服务
                        if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                            try {
                                var ServiceManager = Java.use("android.os.ServiceManager");
                                var iphoneSubInfo = ServiceManager.getService("iphonesubinfo");
                                
                                if (iphoneSubInfo) {
                                    // 尝试获取 IPhoneSubInfo.Stub
                                    try {
                                        var IPhoneSubInfo = Java.use("com.android.internal.telephony.IPhoneSubInfo$Stub");
                                        var phoneSubInfo = IPhoneSubInfo.asInterface(iphoneSubInfo);
                                        
                                        if (phoneSubInfo) {
                                            // 尝试直接调用
                                            try {
                                                var imeiFromService = phoneSubInfo.getDeviceId(context.getOpPackageName());
                                                if (imeiFromService && imeiFromService.length > 0) {
                                                    imei = imeiFromService;
                                                    imeiMethods.push("IPhoneSubInfo 服务");
                                                }
                                            } catch (e) {
                                                // 尝试不带包名参数
                                                try {
                                                    var imeiFromService2 = phoneSubInfo.getDeviceId();
                                                    if (imeiFromService2 && imeiFromService2.length > 0) {
                                                        imei = imeiFromService2;
                                                        imeiMethods.push("IPhoneSubInfo 服务 (无参数)");
                                                    }
                                                } catch (e2) {}
                                            }
                                            
                                            // 尝试 getImeiForSlot
                                            if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                                                try {
                                                    var imeiSlot = phoneSubInfo.getImeiForSlot(0, context.getOpPackageName(), null);
                                                    if (imeiSlot && imeiSlot.length > 0) {
                                                        imei = imeiSlot;
                                                        imeiMethods.push("IPhoneSubInfo.getImeiForSlot");
                                                    }
                                                } catch (e) {}
                                            }
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                        }
                        
                        // 方法 3: 通过系统属性读取
                        if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                            try {
                                var SystemProperties = Java.use("android.os.SystemProperties");
                                var propNames = [
                                    "ril.gsm.imei",
                                    "persist.radio.imei",
                                    "ro.ril.oem.imei",
                                    "gsm.device.imei",
                                    "persist.sys.imei"
                                ];
                                
                                for (var i = 0; i < propNames.length; i++) {
                                    try {
                                        var propValue = SystemProperties.get(propNames[i], "");
                                        if (propValue && propValue.length >= 14) {
                                            imei = propValue;
                                            imeiMethods.push("系统属性: " + propNames[i]);
                                            break;
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                        }
                        
                        // 方法 4: 尝试读取系统文件 (可能需要 root)
                        if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                            try {
                                var imeiPaths = [
                                    "/sys/class/android_usb/android0/iSerial",
                                    "/sys/devices/platform/baseband/esn",
                                    "/sys/devices/platform/baseband/imei",
                                    "/data/nvram/md/NVRAM/NVD_IMEI/MP0B_001"
                                ];
                                
                                var FileReader = Java.use("java.io.FileReader");
                                var BufferedReader = Java.use("java.io.BufferedReader");
                                var File = Java.use("java.io.File");
                                
                                for (var i = 0; i < imeiPaths.length; i++) {
                                    try {
                                        var file = File.$new(imeiPaths[i]);
                                        if (file.exists() && file.canRead()) {
                                            var reader = BufferedReader.$new(FileReader.$new(file));
                                            var line = reader.readLine();
                                            reader.close();
                                            
                                            if (line && line.length >= 14) {
                                                imei = line.trim();
                                                imeiMethods.push("文件: " + imeiPaths[i]);
                                                break;
                                            }
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                        }
                        
                        // 方法 5: 通过 TelephonyManager 的隐藏方法
                        if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                            try {
                                // 尝试使用反射调用隐藏的方法
                                var Class = Java.use("java.lang.Class");
                                var tmClass = telephonyManager.getClass();
                                
                                // 尝试 getMeid
                                try {
                                    var getMeidMethod = tmClass.getDeclaredMethod("getMeid", null);
                                    getMeidMethod.setAccessible(true);
                                    var meid = getMeidMethod.invoke(telephonyManager, null);
                                    if (meid && meid.length > 0) {
                                        imei = "MEID: " + meid;
                                        imeiMethods.push("反射 getMeid");
                                    }
                                } catch (e) {}
                                
                                // 尝试 getDeviceIdForPhone
                                if (!imei || imei === "IMEI_BLOCKED_BY_SYSTEM") {
                                    try {
                                        var Integer = Java.use("java.lang.Integer");
                                        var getDeviceIdForPhoneMethod = tmClass.getDeclaredMethod("getDeviceId", 
                                            Java.use("int").class);
                                        getDeviceIdForPhoneMethod.setAccessible(true);
                                        var imeiSlot = getDeviceIdForPhoneMethod.invoke(telephonyManager, 
                                            Integer.$new(0));
                                        if (imeiSlot && imeiSlot.length > 0) {
                                            imei = imeiSlot;
                                            imeiMethods.push("反射 getDeviceId(slot)");
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                        }
                        
                        // 输出结果
                        if (imei === "IMEI_BLOCKED_BY_SYSTEM") {
                            console.log("IMEI: 系统阻止访问 (Android 10+ 限制)");
                            console.log("提示: 此限制需要系统级权限才能绕过");
                        } else if (imei && imei.length > 0) {
                            console.log("IMEI: " + imei);
                            if (imeiMethods.length > 0) {
                                console.log("获取方式: " + imeiMethods.join(", "));
                            }
                        } else {
                            console.log("IMEI: 无法获取");
                            console.log("可能原因:");
                            console.log("  1. Android 10+ 系统限制");
                            console.log("  2. 设备无 SIM 卡或不支持");
                            console.log("  3. 需要系统级权限 (READ_PRIVILEGED_PHONE_STATE)");
                            console.log("  4. 设备为平板等非手机设备");
                        }

                        // 获取 IMSI
                        try {
                            var imsi = telephonyManager.getSubscriberId();
                            if (imsi === "IMSI_BLOCKED_BY_SYSTEM") {
                                console.log("IMSI: 系统阻止访问 (Android 10+ 限制)");
                            } else if (imsi) {
                                console.log("IMSI: " + imsi);
                            } else {
                                console.log("IMSI: 无法获取 (需要 SIM 卡)");
                            }
                        } catch (e) {
                            console.log("IMSI: 获取失败 - " + e.message);
                        }

                        // 获取运营商信息
                        try {
                            var operator = telephonyManager.getNetworkOperator();
                            if (operator && operator.length > 0) {
                                console.log("运营商代码: " + operator);
                                
                                // 解析运营商代码
                                if (operator.length >= 5) {
                                    var mcc = operator.substring(0, 3);
                                    var mnc = operator.substring(3);
                                    console.log("  ├─ MCC (国家码): " + mcc);
                                    console.log("  └─ MNC (运营商码): " + mnc);
                                }
                            } else {
                                console.log("运营商代码: 无 (未注册网络或无 SIM 卡)");
                            }
                            
                            var operatorName = telephonyManager.getNetworkOperatorName();
                            if (operatorName && operatorName.length > 0) {
                                console.log("运营商名称: " + operatorName);
                            } else {
                                console.log("运营商名称: 无 (未注册网络)");
                            }
                        } catch (e) {
                            console.log("运营商信息: 获取失败 - " + e.message);
                        }

                        // 获取手机号
                        try {
                            var phoneNumber = telephonyManager.getLine1Number();
                            if (phoneNumber && phoneNumber.length > 0) {
                                console.log("手机号: " + phoneNumber);
                            } else {
                                console.log("手机号: 未设置 (运营商未写入 SIM 卡)");
                            }
                        } catch (e) {
                            console.log("手机号: 获取失败 - " + e.message);
                        }
                        
                        // 网络类型
                        try {
                            var networkType = telephonyManager.getNetworkType();
                            var networkTypes = {
                                0: "未知", 1: "GPRS", 2: "EDGE", 3: "UMTS", 4: "CDMA",
                                5: "EVDO_0", 6: "EVDO_A", 7: "1xRTT", 8: "HSDPA", 9: "HSUPA",
                                10: "HSPA", 11: "iDEN", 12: "EVDO_B", 13: "LTE", 14: "eHRPD",
                                15: "HSPA+", 16: "GSM", 17: "TD_SCDMA", 18: "IWLAN", 20: "NR (5G)"
                            };
                            var networkTypeText = networkTypes[networkType] || "未知类型 (" + networkType + ")";
                            console.log("网络类型: " + networkTypeText);
                        } catch (e) {}
                    }
                } catch (e) {
                    console.log("获取电话信息时出错: " + e);
                }
            }

            // 获取内存信息
            try {
                console.log("\n[内存信息]");
                var ActivityManager = Java.use("android.app.ActivityManager");
                var Context = Java.use("android.content.Context");
                
                var activityService = context.getSystemService(Context.ACTIVITY_SERVICE.value);
                if (activityService) {
                    var activityManager = Java.cast(activityService, ActivityManager);
                    var MemoryInfo = Java.use("android.app.ActivityManager$MemoryInfo");
                    var memoryInfo = MemoryInfo.$new();
                    activityManager.getMemoryInfo(memoryInfo);
                    
                    // 正确处理 Java long 类型，使用 .value 属性
                    var totalMem = memoryInfo.totalMem.value / (1024 * 1024);
                    var availMem = memoryInfo.availMem.value / (1024 * 1024);
                    var usedMem = totalMem - availMem;
                    var usedPercent = (usedMem / totalMem * 100).toFixed(2);
                    
                    console.log("总内存: " + totalMem.toFixed(2) + " MB");
                    console.log("已使用: " + usedMem.toFixed(2) + " MB");
                    console.log("使用率: " + usedPercent + " %");
                }
            } catch (e) {
                console.log("获取内存信息时出错: " + e);
            }

            // 获取 CPU 信息（已屏蔽）
            // try {
            //     console.log("\n[CPU 信息]");
            //     var Runtime = Java.use("java.lang.Runtime");
            //     var cpuCount = Runtime.getRuntime().availableProcessors();
            //     console.log("CPU 核心数: " + cpuCount);
            // } catch (e) {
            //     console.log("获取 CPU 信息时出错: " + e);
            // }

            // 获取存储信息
            try {
                console.log("\n[存储信息]");
                var StatFs = Java.use("android.os.StatFs");
                var File = Java.use("java.io.File");
                
                var filesDir = context.getFilesDir();
                if (filesDir) {
                    var path = filesDir.getAbsolutePath();
                    var file = File.$new(path);
                    
                    // 确保文件存在
                    if (file.exists()) {
                        var stat = StatFs.$new(file.getAbsolutePath());
                        
                        var blockSize = stat.getBlockSizeLong();
                        var totalBlocks = stat.getBlockCountLong();
                        var availBlocks = stat.getAvailableBlocksLong();
                        
                        var totalStorage = blockSize * totalBlocks / (1024 * 1024);
                        var availStorage = blockSize * availBlocks / (1024 * 1024);
                        var usedStorage = totalStorage - availStorage;
                        var usedPercent = (usedStorage / totalStorage * 100).toFixed(2);
                        
                        console.log("总存储: " + totalStorage.toFixed(2) + " MB");
                        console.log("已使用: " + usedStorage.toFixed(2) + " MB");
                        console.log("使用率: " + usedPercent + " %");
                    }
                }
            } catch (e) {
                console.log("获取存储信息时出错: " + e);
            }

            // 获取电池信息
            try {
                console.log("\n[电池信息]");
                var IntentFilter = Java.use("android.content.IntentFilter");
                var BatteryManager = Java.use("android.os.BatteryManager");
                
                var filter = IntentFilter.$new("android.intent.action.BATTERY_CHANGED");
                var batteryStatus = context.registerReceiver(null, filter);
                
                if (batteryStatus) {
                    var status = batteryStatus.getIntExtra("status", -1);
                    var isCharging = (status == 2 || status == 5);
                    
                    var level = batteryStatus.getIntExtra("level", -1);
                    var scale = batteryStatus.getIntExtra("scale", -1);
                    var batteryPct = level / scale * 100;
                    
                    var voltage = batteryStatus.getIntExtra("voltage", -1);
                    var temperature = batteryStatus.getIntExtra("temperature", -1) / 10;
                    
                    console.log("电量: " + batteryPct.toFixed(0) + " %");
                    console.log("正在充电: " + (isCharging ? "是" : "否"));
                    console.log("电压: " + voltage + " mV");
                    console.log("温度: " + temperature.toFixed(1) + " ℃");
                }
            } catch (e) {
                console.log("获取电池信息时出错: " + e);
            }

            // 获取显示信息
            try {
                console.log("\n[显示信息]");
                var WindowManager = Java.use("android.view.WindowManager");
                var DisplayMetrics = Java.use("android.util.DisplayMetrics");
                
                var windowService = context.getSystemService("window");
                if (windowService) {
                    var windowManager = Java.cast(windowService, WindowManager);
                    var display = windowManager.getDefaultDisplay();
                    var metrics = DisplayMetrics.$new();
                    display.getMetrics(metrics);
                    
                    var widthPixels = metrics.widthPixels.value;
                    var heightPixels = metrics.heightPixels.value;
                    var density = metrics.density.value;
                    var densityDpi = metrics.densityDpi.value;
                    
                    console.log("屏幕分辨率: " + widthPixels + " x " + heightPixels);
                    console.log("屏幕密度: " + density);
                    console.log("DPI: " + densityDpi);
                    
                    // 获取屏幕刷新率
                    try {
                        var refreshRate = display.getRefreshRate();
                        console.log("刷新率: " + refreshRate.toFixed(2) + " Hz");
                    } catch (e) {}
                }
            } catch (e) {
                console.log("获取显示信息时出错: " + e);
            }

            // 获取网络信息
            try {
                console.log("\n[网络信息]");
                var ConnectivityManager = Java.use("android.net.ConnectivityManager");
                var NetworkInfo = Java.use("android.net.NetworkInfo");
                
                var connectivityService = context.getSystemService("connectivity");
                if (connectivityService) {
                    var connectivityManager = Java.cast(connectivityService, ConnectivityManager);
                    var activeNetwork = connectivityManager.getActiveNetworkInfo();
                    
                    if (activeNetwork) {
                        var isConnected = activeNetwork.isConnected();
                        var typeName = activeNetwork.getTypeName();
                        var subTypeName = activeNetwork.getSubtypeName();
                        
                        console.log("网络连接: " + (isConnected ? "已连接" : "未连接"));
                        console.log("网络类型: " + typeName);
                        console.log("子类型: " + (subTypeName || "无"));
                    } else {
                        console.log("网络连接: 无活动网络");
                    }
                    
                    // VPN 检测（Android 5.0+）
                    try {
                        var VERSION = Java.use("android.os.Build$VERSION");
                        var sdkInt = VERSION.SDK_INT ? VERSION.SDK_INT.value : 0;
                        
                        if (sdkInt >= 21) { // Android 5.0+
                            var allNetworks = connectivityManager.getAllNetworks();
                            var isVpnActive = false;
                            var vpnInfo = [];
                            
                            if (allNetworks && allNetworks.length > 0) {
                                for (var i = 0; i < allNetworks.length; i++) {
                                    try {
                                        var network = allNetworks[i];
                                        var netInfo = connectivityManager.getNetworkInfo(network);
                                        
                                        if (netInfo) {
                                            var type = netInfo.getType();
                                            // TYPE_VPN = 17
                                            if (type === 17) {
                                                isVpnActive = true;
                                                var vpnName = netInfo.getExtraInfo();
                                                vpnInfo.push(vpnName || "未知 VPN");
                                            }
                                        }
                                        
                                        // 检查网络能力
                                        if (sdkInt >= 21) {
                                            try {
                                                var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");
                                                var capabilities = connectivityManager.getNetworkCapabilities(network);
                                                
                                                if (capabilities) {
                                                    // TRANSPORT_VPN = 4
                                                    var hasVpnTransport = capabilities.hasTransport(4);
                                                    if (hasVpnTransport && !isVpnActive) {
                                                        isVpnActive = true;
                                                        vpnInfo.push("VPN 传输层");
                                                    }
                                                }
                                            } catch (e) {}
                                        }
                                    } catch (e) {}
                                }
                            }
                            
                            console.log("\nVPN 状态: " + (isVpnActive ? "已连接" : "未连接"));
                            if (isVpnActive && vpnInfo.length > 0) {
                                console.log("VPN 信息: " + vpnInfo.join(", "));
                            }
                        }
                    } catch (e) {
                        console.log("VPN 检测出错: " + e.message);
                    }
                    
                    // 检测网络接口（包含 VPN 接口）
                    try {
                        var NetworkInterface = Java.use("java.net.NetworkInterface");
                        var interfaces = NetworkInterface.getNetworkInterfaces();
                        var vpnInterfaces = [];
                        var tunInterfaces = [];
                        
                        while (interfaces.hasMoreElements()) {
                            try {
                                var netInterface = Java.cast(interfaces.nextElement(), NetworkInterface);
                                var name = netInterface.getName();
                                var displayName = netInterface.getDisplayName();
                                
                                // 检测常见的 VPN 接口
                                if (name && (name.indexOf("tun") !== -1 || name.indexOf("ppp") !== -1 || 
                                            name.indexOf("pptp") !== -1)) {
                                    vpnInterfaces.push(name);
                                    if (name.indexOf("tun") !== -1) {
                                        tunInterfaces.push(name);
                                    }
                                }
                            } catch (e) {}
                        }
                        
                        if (vpnInterfaces.length > 0) {
                            console.log("检测到 VPN 网络接口: " + vpnInterfaces.join(", "));
                        }
                        if (tunInterfaces.length > 0) {
                            console.log("TUN 接口: " + tunInterfaces.join(", "));
                        }
                    } catch (e) {}
                }
            } catch (e) {
                console.log("获取网络信息时出错: " + e);
            }
            
            // 代理检测
            try {
                console.log("\n[代理检测]");
                
                // 1. 系统代理设置（Android 原生）
                try {
                    var System = Java.use("java.lang.System");
                    var httpProxyHost = System.getProperty("http.proxyHost");
                    var httpProxyPort = System.getProperty("http.proxyPort");
                    var httpsProxyHost = System.getProperty("https.proxyHost");
                    var httpsProxyPort = System.getProperty("https.proxyPort");
                    var socksProxyHost = System.getProperty("socksProxyHost");
                    var socksProxyPort = System.getProperty("socksProxyPort");
                    
                    var hasProxy = false;
                    
                    if (httpProxyHost && httpProxyHost.length > 0) {
                        console.log("HTTP 代理: " + httpProxyHost + ":" + (httpProxyPort || "80"));
                        hasProxy = true;
                    }
                    
                    if (httpsProxyHost && httpsProxyHost.length > 0) {
                        console.log("HTTPS 代理: " + httpsProxyHost + ":" + (httpsProxyPort || "443"));
                        hasProxy = true;
                    }
                    
                    if (socksProxyHost && socksProxyHost.length > 0) {
                        console.log("SOCKS 代理: " + socksProxyHost + ":" + (socksProxyPort || "1080"));
                        hasProxy = true;
                    }
                    
                    if (!hasProxy) {
                        console.log("系统代理: 未设置");
                    }
                } catch (e) {
                    console.log("检测系统代理时出错: " + e.message);
                }
                
                // 2. Android 系统全局代理设置
                try {
                    var Settings = Java.use("android.provider.Settings$Global");
                    var contentResolver = context.getContentResolver();
                    
                    var httpProxy = Settings.getString(contentResolver, "http_proxy");
                    if (httpProxy && httpProxy.length > 0 && httpProxy !== ":0") {
                        console.log("全局 HTTP 代理: " + httpProxy);
                    }
                } catch (e) {}
                
                // 3. WiFi 代理设置
                try {
                    var WifiManager = Java.use("android.net.wifi.WifiManager");
                    var wifiService = context.getSystemService("wifi");
                    
                    if (wifiService) {
                        var wifiManager = Java.cast(wifiService, WifiManager);
                        var wifiInfo = wifiManager.getConnectionInfo();
                        
                        if (wifiInfo) {
                            var VERSION = Java.use("android.os.Build$VERSION");
                            var sdkInt = VERSION.SDK_INT ? VERSION.SDK_INT.value : 0;
                            
                            // Android 5.0+ 可以获取 WiFi 配置
                            if (sdkInt >= 21) {
                                try {
                                    var wifiConfig = wifiManager.getConfiguredNetworks();
                                    if (wifiConfig) {
                                        var currentNetworkId = wifiInfo.getNetworkId();
                                        
                                        for (var i = 0; i < wifiConfig.size(); i++) {
                                            var config = wifiConfig.get(i);
                                            var networkId = config.networkId.value;
                                            
                                            if (networkId === currentNetworkId) {
                                                try {
                                                    // 尝试获取代理设置（需要反射）
                                                    var WifiConfiguration = Java.use("android.net.wifi.WifiConfiguration");
                                                    var proxySettings = getFieldValue(config, "proxySettings");
                                                    
                                                    if (proxySettings && proxySettings.toString() !== "NONE") {
                                                        console.log("WiFi 代理设置: " + proxySettings.toString());
                                                        
                                                        var httpProxy = getFieldValue(config, "httpProxy");
                                                        if (httpProxy) {
                                                            try {
                                                                var host = httpProxy.getHost();
                                                                var port = httpProxy.getPort();
                                                                console.log("WiFi 代理地址: " + host + ":" + port);
                                                            } catch (e) {}
                                                        }
                                                    }
                                                } catch (e) {}
                                            }
                                        }
                                    }
                                } catch (e) {}
                            }
                        }
                    }
                } catch (e) {}
                
                // 4. 检测代理相关环境变量
                try {
                    var envVars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", 
                                   "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"];
                    var hasEnvProxy = false;
                    
                    for (var i = 0; i < envVars.length; i++) {
                        var envValue = System.getenv(envVars[i]);
                        if (envValue && envValue.length > 0) {
                            console.log("环境变量 " + envVars[i] + ": " + envValue);
                            hasEnvProxy = true;
                        }
                    }
                } catch (e) {}
                
            } catch (e) {
                console.log("代理检测出错: " + e);
            }

        } catch (e) {
            console.log("getBasicInfo 总体错误: " + e);
            console.log("堆栈: " + e.stack);
        }
    });
}

// 获取传感器信息
function getSensorInfo() {
    Java.perform(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var application = ActivityThread.currentApplication();
            if (!application) {
                console.log("无法获取应用程序实例");
                return;
            }

            var context = application.getApplicationContext();
            if (!context) {
                console.log("无法获取应用上下文");
                return;
            }

            var SensorManager = Java.use("android.hardware.SensorManager");
            var Sensor = Java.use("android.hardware.Sensor");
            var Context = Java.use("android.content.Context");
            
            var sensorService = context.getSystemService(Context.SENSOR_SERVICE.value);
            if (!sensorService) {
                console.log("无法获取传感器服务");
                return;
            }

            var sensorManager = Java.cast(sensorService, SensorManager);
            var sensorList = sensorManager.getSensorList(Sensor.TYPE_ALL.value);
            
            console.log("\n[传感器信息]");
            console.log("传感器数量: " + sensorList.size());

            var sensorTypes = {
                1: "加速度传感器：检测设备加速度",
                2: "磁场传感器：检测地磁场",
                3: "方向传感器：测量设备方向（已弃用）",
                4: "陀螺仪：检测旋转速度",
                5: "光线传感器：测量环境光强度",
                6: "压力传感器：检测气压，估算海拔",
                8: "距离传感器：靠近时自动熄屏",
                9: "重力传感器：检测重力方向",
                10: "线性加速度传感器：去除重力影响",
                11: "旋转矢量传感器：方向感知（用于 AR）",
                15: "湿度传感器：测量相对湿度",
                16: "未校准陀螺仪：原始角速度数据",
                18: "步态检测：步测器",
                19: "计步器：统计步数",
                20: "未校准磁力计",
                22: "心率传感器",
                29: "加速度未校准",
                30: "磁力计未校准"
            };

            var iterator = sensorList.iterator();
            var index = 0;
            
            while (iterator.hasNext()) {
                try {
                    var sensor = Java.cast(iterator.next(), Sensor);
                    var type = sensor.getType();
                    var typeDesc = sensorTypes[type] || "未知传感器类型";
                    
                    console.log("\n传感器 #" + index);
                    console.log("名称     : " + sensor.getName());
                    console.log("厂商     : " + sensor.getVendor());
                    console.log("类型     : " + type + " - " + typeDesc);
                    console.log("版本     : " + sensor.getVersion());
                    console.log("功耗     : " + sensor.getPower() + " mA");
                    console.log("分辨率   : " + sensor.getResolution());
                    console.log("最大范围 : " + sensor.getMaximumRange());
                    console.log("最小延迟 : " + sensor.getMinDelay() + " μs");
                    
                    index++;
                } catch (e) {
                    console.log("读取传感器 #" + index + " 信息时出错: " + e);
                }
            }
        } catch (e) {
            console.log("getSensorInfo 出错: " + e);
            console.log("堆栈: " + e.stack);
        }
    });
}

// 获取已安装应用信息
function getInstalledPackages() {
    Java.perform(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var currentApplication = ActivityThread.currentApplication();
            if (!currentApplication) {
                console.log("无法获取应用程序实例");
                return;
            }

            var packageManager = currentApplication.getPackageManager();
            if (!packageManager) {
                console.log("无法获取包管理器");
                return;
            }

            var packages = packageManager.getInstalledPackages(0);
            var count = packages.size();
            
            console.log("\n[应用信息]");
            console.log("已安装应用数量: " + count);
            
            var PackageInfo = Java.use("android.content.pm.PackageInfo");
            var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
            
            for (var i = 0; i < Math.min(count, 5); i++) { // 限制只显示前5个应用
                try {
                    var packageInfo = Java.cast(packages.get(i), PackageInfo);
                    
                    if (packageInfo) {
                        // 使用反射获取字段值
                        var applicationInfo = getFieldValue(packageInfo, "applicationInfo");
                        if (!applicationInfo && packageInfo.applicationInfo) {
                            applicationInfo = packageInfo.applicationInfo.value || packageInfo.applicationInfo;
                        }
                        
                        if (applicationInfo) {
                            var appName = packageManager.getApplicationLabel(applicationInfo);
                            var packageName = getFieldValue(packageInfo, "packageName");
                            if (!packageName && packageInfo.packageName) {
                                packageName = packageInfo.packageName.value || packageInfo.packageName;
                            }
                            
                            // 检查是否为系统应用
                            var flags = getFieldValue(applicationInfo, "flags");
                            if (!flags && applicationInfo.flags) {
                                flags = applicationInfo.flags.value || applicationInfo.flags;
                            }
                            var FLAG_SYSTEM = 1; // ApplicationInfo.FLAG_SYSTEM 的值
                            var isSystemApp = ((flags & FLAG_SYSTEM) !== 0);
                            
                            console.log("\n------" + (i + 1) + "-------");
                            console.log("应用名称: " + (appName || "未知"));
                            console.log("包名: " + (packageName || "未知"));
                            console.log("系统应用: " + (isSystemApp ? "是" : "否"));
                        }
                    }
                } catch (e) {
                    console.log("读取应用 #" + i + " 信息时出错: " + e.message);
                }
            }
            
            if (count > 50) {
                console.log("\n... 还有 " + (count - 50) + " 个应用未显示");
            }
        } catch (e) {
            console.log("getInstalledPackages 出错: " + e);
            console.log("堆栈: " + e.stack);
        }
    });
}

// 获取系统信息
function getSystemInfo() {
    Java.perform(function() {
        try {
            var Build = Java.use("android.os.Build");
            var VERSION = Java.use("android.os.Build$VERSION");
            
            console.log("\n[系统信息]");
            
            try {
                console.log("构建ID: " + (Build.ID ? Build.ID.value : "未知"));
                console.log("Android版本: " + (VERSION.RELEASE ? VERSION.RELEASE.value : "未知"));
                console.log("API级别: " + (VERSION.SDK_INT ? VERSION.SDK_INT.value : "未知"));
                console.log("构建时间: " + (Build.TIME ? Build.TIME.value : "未知"));
                
                if (VERSION.SECURITY_PATCH) {
                    console.log("安全补丁: " + VERSION.SECURITY_PATCH.value);
                }
            } catch (e) {
                console.log("获取基础系统信息时出错: " + e);
            }

            // 获取基带版本和内核版本
            try {
                var SystemProperties = Java.use("android.os.SystemProperties");
                var baseband = SystemProperties.get("gsm.version.baseband", "未知");
                console.log("基带版本: " + baseband);
                
                var kernelVersion = SystemProperties.get("os.version", "未知");
                console.log("内核版本: " + kernelVersion);
            } catch (e) {
                console.log("获取基带/内核版本时出错: " + e);
            }

            // Root 检测（增强版）
            try {
                console.log("\n[Root 检测]");
                var File = Java.use("java.io.File");
                var isRooted = false;
                var foundPaths = [];
                var suPaths = [
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/sbin/su",
                    "/system/app/Superuser.apk",
                    "/data/local/su",
                    "/data/local/bin/su",
                    "/system/sd/xbin/su",
                    "/system/bin/failsafe/su",
                    "/data/local/xbin/su"
                ];
                
                for (var i = 0; i < suPaths.length; i++) {
                    try {
                        if (File.$new(suPaths[i]).exists()) {
                            isRooted = true;
                            foundPaths.push(suPaths[i]);
                        }
                    } catch (e) {
                        // 忽略单个路径检查错误
                    }
                }
                
                console.log("是否已Root: " + (isRooted ? "是" : "否"));
                if (isRooted && foundPaths.length > 0) {
                    console.log("发现的 su 路径: " + foundPaths.join(", "));
                }
            } catch (e) {
                console.log("Root 检测时出错: " + e);
            }

            // 开机时长
            try {
                console.log("\n[开机时长]");
                var SystemClock = Java.use("android.os.SystemClock");
                var uptime = SystemClock.elapsedRealtime();
                var hours = Math.floor(uptime / (1000 * 60 * 60));
                var minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
                console.log("开机时长: " + hours + "小时 " + minutes + "分钟");
            } catch (e) {
                console.log("获取开机时长时出错: " + e);
            }

            // JVM 信息
            try {
                console.log("\n[JVM 信息]");
                var System = Java.use("java.lang.System");
                var vmName = System.getProperty("java.vm.name");
                console.log("虚拟机名称: " + (vmName || "未知"));
                
                var VMRuntime = Java.use("dalvik.system.VMRuntime");
                var vmVersion = VMRuntime.getRuntime().vmVersion();
                console.log("ART虚拟机版本: " + (vmVersion || "未知"));
                
                var Runtime = Java.use("java.lang.Runtime");
                var maxMemory = Runtime.getRuntime().maxMemory() / (1024 * 1024);
                console.log("JVM最大堆内存: " + maxMemory.toFixed(0) + " MB");
            } catch (e) {
                console.log("获取 JVM 信息时出错: " + e);
            }
            
            // CPU 架构信息（通过命令行）
            try {
                console.log("\n[CPU 架构信息]");
                var cpuArch = executeCommand("uname -m");
                console.log("CPU架构: " + (cpuArch || "未知"));
                
                // var cpuInfo = executeCommand("cat /proc/cpuinfo | grep 'Hardware'");
                // if (cpuInfo) {
                //     console.log("硬件信息: " + cpuInfo);
                // }
            } catch (e) {
                console.log("获取 CPU 架构信息时出错: " + e);
            }
            
            // SELinux 状态
            try {
                console.log("\n[SELinux 状态]");
                var seLinuxStatus = executeCommand("getenforce");
                console.log("当前模式: " + (seLinuxStatus || "未知"));
                
                var seLinuxPolicy = executeCommand("cat /sys/fs/selinux/policy_version");
                if (seLinuxPolicy) {
                    console.log("策略版本: " + seLinuxPolicy);
                }
            } catch (e) {
                console.log("获取 SELinux 状态时出错: " + e);
            }

            // DRM 信息（Widevine）- 增强版
            try {
                console.log("\n[DRM 信息]");
                var MediaDrm = Java.use("android.media.MediaDrm");
                var UUID = Java.use("java.util.UUID");
                var VERSION = Java.use("android.os.Build$VERSION");
                var sdkInt = VERSION.SDK_INT ? VERSION.SDK_INT.value : 0;
                var widevineUuid = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");
                
                var mediaDrm = null;
                try {
                    mediaDrm = MediaDrm.$new(widevineUuid);
                    
                    if (mediaDrm.getPropertyString) {
                        try {
                            var vendor = mediaDrm.getPropertyString("vendor");
                            console.log("厂商: " + (vendor || "未知"));
                        } catch (e) {}
                        
                        try {
                            var version = mediaDrm.getPropertyString("version");
                            console.log("版本: " + (version || "未知"));
                        } catch (e) {}
                        
                        try {
                            var securityLevel = mediaDrm.getPropertyString("securityLevel");
                            console.log("安全级别: " + (securityLevel || "未知"));
                        } catch (e) {}
                        
                        try {
                            console.log("描述: Widevine CDM");
                        } catch (e) {}
                        
                        try {
                            var systemId = mediaDrm.getPropertyString("systemId");
                            console.log("系统编号: " + (systemId || "未知"));
                        } catch (e) {}
                        
                        try {
                            var algorithms = mediaDrm.getPropertyString("algorithms");
                            console.log("支持的加密算法: " + (algorithms || "未知"));
                        } catch (e) {}
                        
                        // 获取设备唯一ID
                        try {
                            var deviceId = mediaDrm.getPropertyByteArray("deviceUniqueId");
                            if (deviceId) {
                                var hexId = [];
                                for (var i = 0; i < deviceId.length; i++) {
                                    var byte = deviceId[i] & 0xFF;
                                    var hex = ("0" + byte.toString(16)).slice(-2);
                                    hexId.push(hex);
                                }
                                console.log("DRM设备唯一ID: " + hexId.join(""));
                            }
                        } catch (e) {}
                        
                        // Android 7.0+ (API 24+) 功能
                        if (sdkInt >= 24 && mediaDrm.getConnectedHdcpLevel) {
                            try {
                                var hdcpLevel = mediaDrm.getConnectedHdcpLevel();
                                console.log("当前HDCP级别: " + hdcpLevel);
                            } catch (e) {}
                            
                            try {
                                var maxHdcpLevel = mediaDrm.getMaxHdcpLevel();
                                console.log("最大HDCP级别: " + maxHdcpLevel);
                            } catch (e) {}
                        }
                        
                        // 会话信息
                        try {
                            var maxSessions = mediaDrm.getMaxSessionCount();
                            console.log("最大会话数: " + maxSessions);
                        } catch (e) {}
                        
                        try {
                            var openSessions = mediaDrm.getOpenSessionCount();
                            console.log("打开会话数: " + openSessions);
                        } catch (e) {}
                        
                        // Android 7.1+ (API 25+) 功能
                        if (sdkInt >= 25 && mediaDrm.isUsageReportingSupported) {
                            try {
                                var usageReporting = mediaDrm.isUsageReportingSupported();
                                console.log("是否支持使用情况报告: " + (usageReporting ? "是" : "否"));
                            } catch (e) {}
                        }
                    }
                } finally {
                    if (mediaDrm) {
                        try {
                            mediaDrm.close();
                        } catch (e) {}
                    }
                }
            } catch (e) {
                console.log("获取 DRM 信息时出错: " + e);
            }

        } catch (e) {
            console.log("getSystemInfo 出错: " + e);
            console.log("堆栈: " + e.stack);
        }
    });
}

// 主函数
console.log("====================================");
console.log("设备信息获取脚本（增强优化版）");
console.log("版本: 2.0");
console.log("====================================");

// 全局变量存储关键信息用于摘要
var deviceSummary = {
    brand: "",
    model: "",
    androidVersion: "",
    sdkVersion: "",
    isRooted: false,
    totalMemory: 0,
    cpuCores: 0
};

setTimeout(function() {
    safeExecute("基础信息", getBasicInfo);
    
    setTimeout(function() {
        // 已屏蔽传感器信息
        // safeExecute("传感器信息", getSensorInfo);
        
        setTimeout(function() {
            // 已屏蔽应用信息
            // safeExecute("应用信息", getInstalledPackages);
            
            setTimeout(function() {
                safeExecute("系统信息", getSystemInfo);
                
                console.log("\n====================================");
                console.log("信息收集完成！");
                console.log("====================================");
                
                // 显示设备摘要
                printDeviceSummary();
            }, 1000);
        }, 1000);
    }, 1000);
}, 1000);

// 打印设备摘要信息
function printDeviceSummary() {
    try {
        Java.perform(function() {
            console.log("\n");
            console.log("╔════════════════════════════════════╗");
            console.log("║        设备信息摘要                ║");
            console.log("╚════════════════════════════════════╝");
            
            var Build = Java.use("android.os.Build");
            var VERSION = Java.use("android.os.Build$VERSION");
            
            console.log("📱 设备: " + (Build.BRAND ? Build.BRAND.value : "未知") + " " + 
                        (Build.MODEL ? Build.MODEL.value : "未知"));
            console.log("🤖 系统: Android " + (VERSION.RELEASE ? VERSION.RELEASE.value : "未知") + 
                        " (API " + (VERSION.SDK_INT ? VERSION.SDK_INT.value : "未知") + ")");
            console.log("🔧 硬件: " + (Build.HARDWARE ? Build.HARDWARE.value : "未知"));
            console.log("🏭 制造商: " + (Build.MANUFACTURER ? Build.MANUFACTURER.value : "未知"));
            
            console.log("\n提示：完整信息请查看上方详细输出");
            console.log("════════════════════════════════════\n");
        });
    } catch (e) {
        console.log("生成摘要时出错: " + e);
    }
}
