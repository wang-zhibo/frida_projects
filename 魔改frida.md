魔改frida.md


```
git clone https://github.com/frida/frida-core.git


安装子分支

git submodule update --init --recursive

```

```
安装ndk，设置环境变量
https://github.com/android/ndk/wiki  
25版本
设置环境变量


```



```
拉取项目
https://github.com/Ylarod/Florida.git



在 frida-core 项目里
创建文件夹 patch  然后将 Florida 项目里的patches里的 frida-core 目录 挪进来

打上patch

git am patch/frida-core/*.patch
```


```
修改patch的某些部分
g_set_prgname ("ggbond");
```

```
编译
./configure --host=android-arm64

make

```

```
新建一个目录 将 frida-server 文件 和 anti-anti-frida.py (frida-core里src下) 放一起
运行
python anti-anti-frida.py frida-server
```


```

```