运行方式
1:根目录下，执行make指令，得到AccessControl.ko
2根目录下，执行 gcc -o App Application_control.c -lpthread  得到App可执行文件
3.用户登录密码初始化为 54321 ,存储在p.txt文件中，可以用文件编辑器修改。
4.初始的安全文件夹路径为 /home/zsy/demo，可以在程序中修改
5.重载的函数为open rename link symlink rmdir
安全文件夹在访问 重命名 快捷连接 删除等方面做到了管理