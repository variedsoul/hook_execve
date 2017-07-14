功能：
内核层拦截execve，交给用户根据是否含有IN/OUT指令来判断是否要放行。

内核层：
64位下，hook execve 在可以用jprobe的方式。但是jprobe好像会让这个新的函数处于中断上下文。

需要在新的函数中做到和用户程序的同步通信，即，发送数据给用户程序，等待其回复后，才能继续执行。
这样就会阻塞，而中断上下文不允许阻塞。所以现在暂时只是发送数据给用户程序，而不等待其回复。

netlink是异步通信，在内核层被动接收来自用户程序的数据，有个回调函数，当接收到数据时，进入回调函数处理。
http://codefine.co/121.html
http://www.cnblogs.com/hoys/archive/2011/04/09/2010788.html
http://blog.csdn.net/lesleylily/article/details/49300813

用户程序：
首先发送个信息给内核，让内核知道是哪个进程再跟他通信。
然后开始接受来自内核的消息。每次接收到消息后，存储到一个环形缓冲区中。一个线程从环形缓冲区中读取内容，读取到之后用
objdump -d XXX|grep -E '[[:space:]](out|in) '|wc -l
（注意grep要加 -E表示扩展，否则'|'不能用）来看汇编中是否有in或out指令，是的话，发送deny给内核，否则发送pass。同时记录日志。

这里有个坑，就是user程序里会执行objdump -d XXX|grep -E '[[:space:]](out|in) '|wc -l 时，也会调用execve，内核又发送消息给user，user又调用这个命令，然后就会形成一个死循环。一开始我的解决方法是用个count在新的exece里计数，因为是多了sh，objdump，grep，wc这四个执行，所以每次数到5才发送，否则不发送。但是后来发现这个方法有问题，这5个中间如果穿插了别的，还是会死循环。后来想用找祖先的方法判断执行execve的当前进程是否是由user创建的，是的话就不发送。但是发现这些子进程的父进程并不是我想的那样就是user，后来还是用这种方法解决了，用的是tgid。

64位下用修改syscalltable的方式来hook execve的方法。还有反汇编的库……
https://github.com/kfiros/execmon/blob/8988bb076f8b3f45fd8a005e8cc4ebc76433564b/kmod/syscalls.c
