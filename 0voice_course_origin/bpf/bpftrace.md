


## bpftrace进行内核跟踪


#### bpftrace 命令行操作
单行命令工具：
```
bpftrace -e 'program'
```

bpftrace直接跟-e选项后面加单行命令，一些示例，比如：
```
bpftrace -e 'BEGIN { printf("Hello world!\n"); }'
bpftrace -e 'kprobe:vfs_read { @[tid] = count();}'
bpftrace -e 'kprobe:vfs_read  /pid == 123/ { @[tid, comm] = count();}'
bpftrace -e 't:block:block_rq_insert { @[kstack] = count(); }'
```

单行命令工具可以按ctrl-c也结束，只有结束后才会打印输出结果。

#### bpftrace 编写脚本工具
bpftrace支持脚本编写，只需要在其实出添加#!/usr/local/bin/bpftrace，会被认为是一个bpftrace脚本。

```
#!/usr/local/bin/bpftrace
// this program times vfs_read()
kprobe:vfs_read
{
    @start[tid] = nsecs;
} 
retprobe:vfs_read
/@start[tid]/
{
    $duration_us = (nsecs - @start[tid]) / 1000;
    @us = hist($duration_us);
    delete(@start[tid]);
}

```

#### debug调试
```
bpftrace -d
bpftrace -v
```

bpftrace语法结构
bpftrace编程语言参考了awk的语法，基础结构：
```
probes /filter/ { actions }
```

它是一种事件驱动的运行方式。
probes表示的就是事件，包括tracepoint、kprobe、kretprobe、uprobe等等。除了这些跟踪点，还有两个特殊的事件BEGIN、END，用于在脚本开始处和结束处执行。

filter表示的是过滤条件，当一个事件触发时，会先判断该条件，满足条件才会执行后面的action行为。

action表示的具体执行的操作。
示例：
```
bpftrace -e 'kprobe:vfs_read  /pid == 123/ { @[tid, comm] = count();}'
```

#### bpftrace 脚本变量

内部变量（built-in）
```
uid:    用户id。
tid：   线程id
pid：   进程id。
cpu：   cpu id。
cgroup：cgroup id.
probe： 当前的trace点。
comm：  进程名字。
nsecs： 纳秒级别的时间戳。
kstack：内核栈描述
curtask：当前进程的task_struct地址。
args:   获取该kprobe或者tracepoint的参数列表
arg0:   获取该kprobe的第一个变量，tracepoint不可用
arg1:   获取该kprobe的第二个变量，tracepoint不可用
arg2:   获取该kprobe的第三个变量，tracepoint不可用
retval: kretprobe中获取函数返回值
args->ret: kretprobe中获取函数返回值
```
备注：
```
bpftrace -lv tracepoint:syscalls:sys_enter_read
```
这个命令-lv可以用来查看一个tracepoint对应的参数都有哪些。

自定义临时变量
以"$"标志起始来定义和引用一个变量
```
$x = 1
```
Map变量
map变量是用于内核向用户空间传递数据的一种存储结构，定义方式是以"@"符号作为其实标记。
这个map可以有单个key或者多个key：
```
@path[tid] = nsecs
@path[pid, $fd] =nsecs
```
bpftrace默认在结束时会打印从内核接收到的map变量。

#### 函数
```
exit():退出bpftrace程序
str(char *):转换一个指针到string类型
system(format[, arguments ...]):运行一个shell命令
join(char *str[]):打印一个字符串列表并在每个前面加上空格，比如可以用来输出args->argv
ksym(addr)：用于转换一个地址到内核symbol
kaddr(char *name):通过symbol转换为内核地址
print(@m [, top [, div]])：可选择参数打印map中的top n个数据，数据可选择除以一个div值
```

#### map函数
bpftrace内构的一些map函数，用于传递数据给map变量，注意接收他们的变量是map类型。常用的包括：
```
count():用于计算次数
sum(int n):用于累加计算
avg(int n):用于计算平均值
min(int n):用于计算最小值
max(int n):用于计算最大值
hist(int n):数据分布直方图（范围为2的幂次增长）
lhist(int n)：数据线性直方图
delete(@m[key]):删除map中的对应的key数据
clear(@m):删除map中的所有数据
zero(@m):map中的所有值设置为0
```


#### 附件
常用的一些单行命令示例：
```
bpftrace -e 'tracepoint:block:block_rq_i* { @[probe] = count(); } interval:s:1 { print(@); clear(@); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret > 0/ { @bytes = sum(args->ret); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @ret = hist(args->ret); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @ret = lhist(args->ret, 0, 1000, 100); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret < 0/ { @[- args->ret] = count(); }'
bpftrace -e 'kprobe:vfs_* { @[probe] = count(); } END { print(@, 5); clear(@); }'
bpftrace -e 'kprobe:vfs_read { @start[tid] =nsecs; } kretprobe:vfs_read /@start[tid]/ { @ms[comm] = sum(nsecs - @start[tid]); delete(@start[tid]); } END { print(@ms, 0, 1000000); clear(@ms); clear(@start); }'
bpftrace -e 'k:vfs_read { @[pid] = count(); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s -> %s\n", comm, str(args->filename)); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
bpftrace -e 'tracepoint:raw_syscalls:sys_enter {@[comm] = count(); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_* {@[probe] = count(); }'
bpftrace -e 'tracepoint:raw_syscalls:sys_enter {@[pid, comm] = count(); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read /args->ret/ { @[comm] = sum(args->ret); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_read { @[comm] = hist(args->ret); }'
bpftrace -e 'tracepoint:block:block_rq_issue { printf("%d %s %d\n", pid, comm, args->bytes); }'
bpftrace -e 'software:major-faults:1 { @[comm] = count(); }'
bpftrace -e 'software:faults:1 { @[comm] = count(); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_clone { printf("-> clone() by %s PID %d\n", comm, pid); } tracepoint:syscalls:sys_exit_clone { printf("<- clone() return %d, %s PID %d\n", args->ret, comm, pid); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_setuid { printf("setuid by PID %d (%s), UID %d\n", pid, comm, uid); }'
bpftrace -e 'tracepoint:syscalls:sys_exit_setuid { printf("setuid by %s returned %d\n", comm, args->ret); }'
bpftrace -e 'tracepoint:block:block_rq_insert { printf("Block I/O by %s\n", kstack); }'
bpftrace -e 'tracepoint:syscalls:sys_enter_connect /pid == 123/ { printf("PID %d called connect()\n", $1); }'
bpftrace -e 'tracepoint:timer:hrtimer_start { @[ksym(args->function)] = count(); }'
bpftrace -e 't:syscalls:sys_enter_read { @reads = count(); } interval:s:5 { exit(); }'
bpftrace -e 'kprobe:vfs_read {@ID = pid;} interval:s:2 {printf("ID:%d\n", @ID);}'
```