'''
volatility pslist two ways.
By: Luke Craig
'''

import volatility.addrspace as  addrspace
import volatility.registry as registry
import volatility.conf as conf
from pandare import Panda, blocking
from sys import argv
from time import time
from volatility.plugins.gui import windows
from volatility.plugins.taskmods import PSList
from volatility.plugins.gui.windowstations import WndScan
# from volatility.framework.objects import utility

arch = "i386" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait"
qcow = "win7_32bit.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="8G")


registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.panda = panda
# config.
config.PROFILE = "Win7SP1x86_23418"
config.LOCATION = "panda://asdf"
config.VERBOSE = True
# config.LOCATION = "~/workspace/volatility/dump.out"


main_desktop = None

def get_desktop_wins(d):
    windows = []
    win = d.DeskInfo.spwnd
    for w,level in d.windows(win=win, fltr=lambda x: 'WS_VISIBLE' in str(x.style)):
        windows.append(w)
    return windows

def get_windows():
    global main_desktop, config
    if main_desktop:
        return get_desktop_wins(main_desktop)
    wnd = WndScan(config)
    for w in wnd.calculate():
        for d in w.desktops():
            windows = get_desktop_wins(d)
            if any(w.rcWindow.left != 0 for w in windows):
                main_desktop = d
                return windows

def get_processes():
    psl = PSList(config)
    return [
        {
            "Name": str(task.ImageFileName or ''),
            "PID": task.UniqueProcessId,
            "PPID": task.InheritedFromUniqueProcessId,
            "Thds": task.ActiveThreads,
            "Hnds": task.ObjectTable.HandleCount,
            "Sess": task.SessionId,
            "Wow64": task.Wow64Process,
            "Start": task.CreateTime,
            "Exit": task.ExitTime,
        }
        for task in psl.calculate()
    ]

@panda.queue_blocking
def b():
    panda.revert_sync("cmdP")
    

@panda.cb_asid_changed
def asid_changed(cpu, old, new):
    procs = get_processes()
    
    print("First 5 processes")
    for i in range(5):
        print(procs[i])
    
    windows = get_windows()
    for i,w in enumerate(windows):
        print(f"Window #{i}: Name: '{str(w.strName or '')}'  Position: {w.rcWindow.get_tup()}")
    
    # sh = Screenshot(config)
    # sh.execute()
    breakpoint()
    print("asdf")
    # for i in pst.calculate():
        # print(i)
    panda.end_analysis()



panda.run()
