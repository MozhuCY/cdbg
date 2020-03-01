# cdbg

一个ptrace实现的小调试器,用来做vm的逆向题目,可以省去打log的步骤.

用法:addBp(address,regname),然后编译运行

## V 0.01

目前完成了下断点和continue的功能.

可以监视目标位置的寄存器值,对于变种vm还未进行测试
