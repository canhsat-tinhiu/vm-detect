from typing import Dict, List, Any, Optional, Tuple
import wmi
import winreg
import os
import sys
import socket
import subprocess
import ctypes
import platform
import time
import psutil
import requests
import uuid
import hashlib
import struct
from ctypes import (
    windll, c_uint, c_ulonglong, byref, c_bool, 
    c_char_p, c_wchar_p, Structure, Union, c_long  # Thêm c_long vào đây
)
from ctypes import windll, c_uint, c_ulonglong, byref, c_bool, c_char_p, c_wchar_p, Structure, Union
from ctypes.wintypes import DWORD, HANDLE, LPWSTR, WORD, BYTE
import threading
from datetime import datetime
import re

# Telegram config
BOT_TOKEN = 'YOUR-BOT-TOKEN-HERE'
CHAT_ID = 'YOUR-CHATID-HERE'

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
VIRTUAL_MEM = (MEM_COMMIT | MEM_RESERVE)

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", c_ulonglong),
        ("lpMaximumApplicationAddress", c_ulonglong),
        ("dwActiveProcessorMask", c_ulonglong),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD)
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_ulonglong),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
    ]

class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", c_ulonglong),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", c_long),
        ("dwFlags", DWORD),
        ("szExeFile", c_char_p * 260)
    ]

class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", c_ulonglong),
        ("modBaseSize", DWORD),
        ("hModule", HANDLE),
        ("szModule", c_char_p * 256),
        ("szExePath", c_char_p * 260)
    ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", c_long),
        ("tpDeltaPri", c_long),
        ("dwFlags", DWORD)
    ]

class DeviceFingerprint:
    """Tạo fingerprint cho thiết bị dựa trên thông tin phần cứng"""

    @staticmethod
    def get_hardware_info() -> Dict[str, Any]:
        hw_info = {}
        
        try:
            wmi_obj = wmi.WMI()
            
            # CPU Info
            cpu = wmi_obj.Win32_Processor()[0]
            hw_info['cpu'] = {
                'id': cpu.ProcessorId.strip() if cpu.ProcessorId else '',
                'name': cpu.Name.strip(),
                'cores': cpu.NumberOfCores,
                'threads': cpu.NumberOfLogicalProcessors
            }
            
            # BIOS Info
            bios = wmi_obj.Win32_BIOS()[0]
            hw_info['bios'] = {
                'manufacturer': bios.Manufacturer.strip(),
                'version': bios.Version.strip(),
                'serial': bios.SerialNumber.strip() if bios.SerialNumber else ''
            }
            
            # Motherboard Info
            board = wmi_obj.Win32_BaseBoard()[0]
            hw_info['motherboard'] = {
                'manufacturer': board.Manufacturer.strip(),
                'product': board.Product.strip(),
                'serial': board.SerialNumber.strip() if board.SerialNumber else ''
            }
            
            # Storage Info
            disks = []
            for disk in wmi_obj.Win32_DiskDrive():
                disks.append({
                    'model': disk.Model.strip(),
                    'size': disk.Size,
                    'serial': disk.SerialNumber.strip() if disk.SerialNumber else ''
                })
            hw_info['storage'] = disks
            
            # Network Adapters
            nics = []
            for nic in wmi_obj.Win32_NetworkAdapter(PhysicalAdapter=True):
                if nic.MACAddress:
                    nics.append({
                        'name': nic.Name.strip(),
                        'mac': nic.MACAddress.strip(),
                        'adapter_type': nic.AdapterType.strip() if nic.AdapterType else ''
                    })
            hw_info['network'] = nics
            
        except Exception as e:
            hw_info['error'] = str(e)
            
        return hw_info

    @staticmethod
    def generate_fingerprint() -> str:
        """Tạo fingerprint duy nhất cho thiết bị"""
        hw_info = DeviceFingerprint.get_hardware_info()
        
        # Tạo chuỗi đặc trưng từ thông tin phần cứng
        fingerprint_str = ''
        
        if 'cpu' in hw_info:
            fingerprint_str += hw_info['cpu'].get('id', '')
            
        if 'bios' in hw_info:
            fingerprint_str += hw_info['bios'].get('serial', '')
            
        if 'motherboard' in hw_info:
            fingerprint_str += hw_info['motherboard'].get('serial', '')
            
        if 'storage' in hw_info:
            for disk in hw_info['storage']:
                fingerprint_str += disk.get('serial', '')
                
        if 'network' in hw_info:
            for nic in hw_info['network']:
                fingerprint_str += nic.get('mac', '')
                
        # Hash chuỗi đặc trưng
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

class SystemUtils:
    """Các utility functions để tương tác với hệ thống"""
    
    @staticmethod
    def get_process_list() -> List[Dict[str, Any]]:
        """Lấy danh sách process đang chạy"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                proc_info = proc.info
                proc_info['cmdline'] = proc.cmdline()
                proc_info['created_time'] = proc.create_time()
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    @staticmethod
    def get_loaded_dlls(pid: int) -> List[str]:
        """Lấy danh sách DLL được load bởi process"""
        try:
            process = psutil.Process(pid)
            return [dll.path for dll in process.memory_maps()]
        except:
            return []

    @staticmethod
    def check_file_exists(filepath: str) -> bool:
        """Kiểm tra file có tồn tại không"""
        return os.path.exists(filepath)

    @staticmethod
    def get_file_info(filepath: str) -> Dict[str, Any]:
        """Lấy thông tin chi tiết của file"""
        file_info = {}
        try:
            stat = os.stat(filepath)
            file_info.update({
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
                'mode': stat.st_mode
            })
            
            if sys.platform == 'win32':
                # Windows specific file info
                try:
                    import win32api
                    info = win32api.GetFileVersionInfo(filepath, "\\")
                    ms = info['FileVersionMS']
                    ls = info['FileVersionLS']
                    file_info['version'] = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
                except:
                    pass
                    
        except Exception as e:
            file_info['error'] = str(e)
            
        return file_info

    @staticmethod
    def is_admin() -> bool:
        """Kiểm tra có quyền admin không"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

def send_telegram_message(message: str, bot_token: str, chat_id: str) -> bool:
    """Gửi tin nhắn qua Telegram"""
    try:
        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        response = requests.post(url, json=payload)
        return response.status_code == 200
    except Exception as e:
        print(f"Lỗi khi gửi tin nhắn Telegram: {str(e)}")
        return False


class AdvancedEnvironmentDetector:
    def __init__(self):
        self.wmi = wmi.WMI()
        self.kernel32 = windll.kernel32
        self.ntdll = windll.ntdll
        self.user32 = windll.user32
        self.advapi32 = windll.advapi32
        
        # System info
        self.system_info = SYSTEM_INFO()
        self.kernel32.GetSystemInfo(byref(self.system_info))
        
        # Các hằng số Windows API
        self.STANDARD_RIGHTS_READ = 0x00020000
        self.TOKEN_QUERY = 0x0008
        self.TOKEN_READ = (self.STANDARD_RIGHTS_READ | self.TOKEN_QUERY)
        
        # Fingerprint của thiết bị
        self.device_fingerprint = DeviceFingerprint.generate_fingerprint()
        
        # Khởi tạo cache
        self.cache = {}

    def check_environment(self) -> Dict[str, Any]:
        """Kiểm tra toàn diện môi trường"""
        results = {
            'device_info': self._get_device_info(),
            'virtualization': self._check_virtualization(),
            'debugging': self._check_debugging(),
            'sandbox': self._check_sandbox(),
            'analysis_tools': self._check_analysis_tools(),
            'rootkit': self._check_rootkit(),
            'memory': self._check_memory(),
            'network': self._check_network(),
            'timing': self._check_timing(),
            'artifacts': self._check_artifacts()
        }
        return results
    def _check_network(self) -> Dict[str, Any]:
        """Kiểm tra các kết nối mạng đáng ngờ"""
        try:
            network_checks = {
                'suspicious_connections': self._check_suspicious_connections(),
                'dns_servers': self._get_dns_servers(),
                'network_shares': self._get_network_shares()
            }
            return network_checks
        except Exception as e:
            # Trả về dict rỗng nếu lỗi xảy ra
            return {}
    def _get_device_info(self) -> Dict[str, Any]:
        """Thu thập thông tin chi tiết về thiết bị"""
        info = {
            'fingerprint': self.device_fingerprint,
            'hardware': {},
            'software': {},
            'network': {},
            'security': {}
        }
        
        try:
            # Hardware info
            info['hardware'].update({
                'cpu': self._get_cpu_info(),
                'memory': self._get_memory_info(),
                'disks': self._get_disk_info(),
                'gpu': self._get_gpu_info(),
                'mainboard': self._get_mainboard_info(),
                'bios': self._get_bios_info()
            })
            
            # Software info
            info['software'].update({
                'os': self._get_os_info(),
                'installed_software': self._get_installed_software(),
                'running_services': self._get_running_services(),
                'startup_items': self._get_startup_items(),
                'scheduled_tasks': self._get_scheduled_tasks()
            })
            
            # Network info
            info['network'].update({
                'adapters': self._get_network_adapters(),
                'connections': self._get_network_connections(),
                'dns_config': self._get_dns_config(),
                'routing_table': self._get_routing_table(),
                'shared_resources': self._get_shared_resources()
            })
            
            # Security info
            info['security'].update({
                'antivirus': self._get_antivirus_info(),
                'firewall': self._get_firewall_info(),
                'updates': self._get_windows_updates(),
                'uac_level': self._get_uac_level(),
                'privileges': self._get_current_privileges()
            })
            
        except Exception as e:
            info['error'] = str(e)
            
        return info

    def _get_cpu_info(self) -> Dict[str, Any]:
        """Thu thập thông tin chi tiết về CPU"""
        cpu_info = {}
        
        try:
            cpu = self.wmi.Win32_Processor()[0]
            cpu_info.update({
                'name': cpu.Name.strip(),
                'manufacturer': cpu.Manufacturer.strip(),
                'description': cpu.Description.strip(),
                'architecture': cpu.Architecture,
                'max_clock_speed': cpu.MaxClockSpeed,
                'current_clock_speed': cpu.CurrentClockSpeed,
                'number_of_cores': cpu.NumberOfCores,
                'number_of_logical_processors': cpu.NumberOfLogicalProcessors,
                'l2_cache_size': cpu.L2CacheSize,
                'l3_cache_size': cpu.L3CacheSize,
                'socket_designation': cpu.SocketDesignation,
                'processor_id': cpu.ProcessorId.strip() if cpu.ProcessorId else '',
                'current_voltage': cpu.CurrentVoltage,
                'status': cpu.Status,
                'characteristics': cpu.Characteristics if hasattr(cpu, 'Characteristics') else None
            })
            
            # CPU Usage Information
            cpu_times = psutil.cpu_times_percent()
            cpu_info['usage'] = {
                'user': cpu_times.user,
                'system': cpu_times.system,
                'idle': cpu_times.idle,
                'interrupt': cpu_times.interrupt,
                'dpc': cpu_times.dpc if hasattr(cpu_times, 'dpc') else None
            }
            
            # CPU Frequency
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                cpu_info['frequency'] = {
                    'current': cpu_freq.current,
                    'min': cpu_freq.min,
                    'max': cpu_freq.max
                }
            
            # Advanced CPU features
            cpu_info['features'] = {
                'vmx': self._check_cpu_feature('vmx'),
                'nx': self._check_cpu_feature('nx'),
                'aes': self._check_cpu_feature('aes'),
                'sse': self._check_cpu_feature('sse'),
                'avx': self._check_cpu_feature('avx')
            }
            
        except Exception as e:
            cpu_info['error'] = str(e)
            
        return cpu_info

    def _check_cpu_feature(self, feature: str) -> bool:
        """Kiểm tra các tính năng CPU cụ thể"""
        try:
            import cpuinfo
            features = cpuinfo.get_cpu_info()['flags']
            return feature.lower() in features
        except:
            return False

    def _get_memory_info(self) -> Dict[str, Any]:
        """Thu thập thông tin chi tiết về bộ nhớ"""
        memory_info = {}
        
        try:
            # Virtual Memory
            virtual = psutil.virtual_memory()
            memory_info['virtual'] = {
                'total': virtual.total,
                'available': virtual.available,
                'used': virtual.used,
                'free': virtual.free,
                'percent': virtual.percent,
                'active': virtual.active if hasattr(virtual, 'active') else None,
                'inactive': virtual.inactive if hasattr(virtual, 'inactive') else None,
                'buffers': virtual.buffers if hasattr(virtual, 'buffers') else None,
                'cached': virtual.cached if hasattr(virtual, 'cached') else None,
                'shared': virtual.shared if hasattr(virtual, 'shared') else None
            }
            
            # Swap Memory
            swap = psutil.swap_memory()
            memory_info['swap'] = {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'sin': swap.sin,
                'sout': swap.sout
            }
            
            # Physical Memory Slots
            physical_memory = []
            for mem in self.wmi.Win32_PhysicalMemory():
                physical_memory.append({
                    'capacity': mem.Capacity,
                    'clock_speed': mem.ConfiguredClockSpeed,
                    'form_factor': mem.FormFactor,
                    'location': mem.DeviceLocator,
                    'manufacturer': mem.Manufacturer,
                    'part_number': mem.PartNumber,
                    'serial_number': mem.SerialNumber,
                    'memory_type': mem.SMBIOSMemoryType,
                    'type_detail': mem.TypeDetail,
                    'speed': mem.Speed,
                    'total_width': mem.TotalWidth,
                    'data_width': mem.DataWidth,
                    'rank': mem.Rank if hasattr(mem, 'Rank') else None
                })
            memory_info['physical_memory_slots'] = physical_memory
            
            # Memory Regions
            memory_info['regions'] = self._get_memory_regions()
            
        except Exception as e:
            memory_info['error'] = str(e)
            
        return memory_info
    def _check_virtualization(self) -> Dict[str, Any]:
        """Kiểm tra toàn diện dấu hiệu ảo hóa"""
        vm_checks = {
            'files': self._check_vm_files(),
            'registry': self._check_vm_registry(),
            'processes': self._check_vm_processes(),
            'services': self._check_vm_services(),
            'drivers': self._check_vm_drivers(),
            'mac_addresses': self._check_vm_mac(),
            'hardware': self._check_vm_hardware(),
            'system': self._check_vm_system(),
            'artifacts': self._check_vm_artifacts()
        }

        # Tính toán điểm số ảo hóa
        score = 0
        reasons = []

        def add_score(points: int, reason: str):
            nonlocal score
            score += points
            reasons.append(reason)

    # Kiểm tra từng loại dấu hiệu
        if vm_checks['files']:
            add_score(20, f"Phát hiện {len(vm_checks['files'])} files máy ảo")

        if vm_checks['registry']:
            add_score(15, f"Phát hiện {len(vm_checks['registry'])} registry keys máy ảo")

        if vm_checks['processes']:
            add_score(25, f"Phát hiện {len(vm_checks['processes'])} processes máy ảo")

        if vm_checks['services']:
            add_score(20, f"Phát hiện {len(vm_checks['services'])} services máy ảo")

        if vm_checks['drivers']:
            add_score(25, f"Phát hiện {len(vm_checks['drivers'])} drivers máy ảo")

        if vm_checks['mac_addresses']:
            add_score(15, "Phát hiện MAC address máy ảo")

        if vm_checks['hardware'].get('is_virtual', False):
            add_score(30, "Phát hiện hardware ảo")

        vm_checks.update({
            'score': score,
            'reasons': reasons,
            'is_virtual': score >= 50  # Ngưỡng 50 điểm
        })

        return vm_checks

    def _check_vm_files(self) -> List[str]:
        """Kiểm tra các file đặc trưng của máy ảo"""
        vm_files = [
            r"C:\Windows\System32\drivers\vmmouse.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
            r"C:\Windows\System32\drivers\VBoxMouse.sys",
            r"C:\Windows\System32\drivers\VBoxGuest.sys",
            r"C:\Windows\System32\drivers\VBoxSF.sys",
            r"C:\Windows\System32\drivers\VBoxVideo.sys",
            r"C:\Windows\System32\vboxdisp.dll",
            r"C:\Windows\System32\vboxhook.dll",
            r"C:\Windows\System32\vboxmrxnp.dll",
            r"C:\Windows\System32\vboxogl.dll",
            r"C:\Windows\System32\vboxoglarrayspu.dll",
            r"C:\Windows\System32\vboxoglcrutil.dll",
            r"C:\Windows\System32\vboxoglerrorspu.dll",
            r"C:\Windows\System32\vboxoglfeedbackspu.dll",
            r"C:\Windows\System32\vboxoglpackspu.dll",
            r"C:\Windows\System32\vboxoglpassthroughspu.dll",
            r"C:\Windows\System32\vboxservice.exe",
            r"C:\Windows\System32\vboxtray.exe",
            r"C:\Windows\System32\VBoxControl.exe",
            r"C:\Windows\System32\drivers\vmsrvc.sys",
            r"C:\Windows\System32\drivers\vpc-s3.sys",
            r"C:\Windows\System32\drivers\vpcbus.sys",
            r"C:\Windows\System32\drivers\vpcuhub.sys",
            r"C:\Windows\System32\drivers\vpcusb.sys",
            r"C:\Windows\System32\drivers\vmci.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
            r"C:\Windows\System32\drivers\vmmemctl.sys",
            r"C:\Windows\System32\drivers\vmx86.sys",
            r"C:\Windows\System32\drivers\vmxnet.sys"
        ]
        return [f for f in vm_files if os.path.exists(f)]

    def _check_vm_registry(self) -> List[str]:
        """Kiểm tra registry keys đặc trưng của máy ảo"""
        vm_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxMouse"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxService"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxSF"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxVideo"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System\SystemBiosVersion"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System\VideoBiosVersion"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMTools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
        ]
        
        found_keys = []
        for hkey, path in vm_keys:
            try:
                winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                found_keys.append(path)
            except WindowsError:
                continue
        return found_keys

    def _check_vm_processes(self) -> List[str]:
        """Kiểm tra các process đặc trưng của máy ảo"""
        vm_processes = [
            'vmtoolsd.exe',
            'vmwaretray.exe',
            'vmwareuser.exe',
            'VBoxService.exe',
            'VBoxTray.exe',
            'vmsrvc.exe',
            'vmusrvc.exe',
            'prl_tools_service.exe',
            'prl_tools.exe',
            'prl_cc.exe',
            'xenservice.exe',
            'qemu-ga.exe',
            'vmware-vmx.exe',
            'vmware-authd.exe',
            'vmware-hostd.exe',
            'vmware-tray.exe',
            'vmware-unity-helper.exe',
            'vm3dservice.exe',
            'vmwareservice.exe',
            'vmwaretray.exe',
            'vmwareuser.exe',
            'vboxservice.exe',
            'vboxtray.exe'
        ]

        found_processes = []
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in map(str.lower, vm_processes):
                    found_processes.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found_processes

    def _check_vm_services(self) -> List[str]:
        """Kiểm tra các service đặc trưng của máy ảo"""
        vm_services = [
            'vmtools',
            'vboxservice',
            'vmhgfs',
            'vmvss',
            'vmscsi',
            'vmxnet',
            'vmx86',
            'vmmouse',
            'vmrawdsk',
            'vmusbmouse',
            'vmvideo',
            'vmware',
            'vmci',
            'vmmemctl',
            'vmxnet3',
            'hypervvssd',
            'hypervvideo',
            'hypervkvpexchange',
            'hypervintegrationservice',
            'vmicshutdown',
            'vmicheartbeat',
            'vmicrdv',
            'vmictimesync'
        ]

        found_services = []
        for service in psutil.win_service_iter():
            try:
                if service.name().lower() in map(str.lower, vm_services):
                    found_services.append(service.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found_services

    def _check_vm_drivers(self) -> List[str]:
        """Kiểm tra các driver đặc trưng của máy ảo"""
        vm_drivers = [
            'vboxdrv',
            'vboxguest',
            'vboxmouse',
            'vboxsf',
            'vboxvideo',
            'vmci',
            'vmhgfs',
            'vmmouse',
            'vmscsi',
            'vmx86',
            'vmxnet',
            'vmxnet3',
            'hv_vmbus',
            'hv_netvsc',
            'hv_storvsc'
        ]

        found_drivers = []
        try:
            # Sử dụng WMI để lấy danh sách drivers
            for driver in self.wmi.Win32_SystemDriver():
                if any(vm_driver in driver.Name.lower() for vm_driver in vm_drivers):
                    found_drivers.append(driver.Name)
        except:
            pass
        return found_drivers

    def _check_vm_mac(self) -> List[str]:
        """Kiểm tra MAC address đặc trưng của máy ảo"""
        vm_mac_prefixes = [
            '00:05:69',  # VMware
            '00:0C:29',  # VMware
            '00:1C:14',  # VMware
            '00:50:56',  # VMware
            '00:15:5D',  # Hyper-V
            '00:16:3E',  # Xen
            '08:00:27',  # VirtualBox
            '52:54:00',  # QEMU/KVM
            'FA:16:3E'   # Oracle
        ]

        found_macs = []
        for nic in self.wmi.Win32_NetworkAdapter():
            if nic.MACAddress:
                mac = nic.MACAddress.lower()
                for prefix in vm_mac_prefixes:
                    if mac.startswith(prefix.lower()):
                        found_macs.append(mac)
        return found_macs
    def _check_vm_hardware(self) -> Dict[str, bool]:
        """Kiểm tra phần cứng đáng ngờ"""
        hardware_checks = {
            'is_virtual': False,
            'low_memory': False,
            'low_cpu_cores': False,
            'suspicious_gpu': False,
            'suspicious_disk': False,
            'suspicious_bios': False,
            'suspicious_manufacturer': False
        }

        try:
            # Kiểm tra CPU
            cpu = self.wmi.Win32_Processor()[0]
            hardware_checks['low_cpu_cores'] = int(cpu.NumberOfCores) <= 2
            
            # Kiểm tra RAM
            memory = psutil.virtual_memory()
            hardware_checks['low_memory'] = memory.total < 4 * 1024 * 1024 * 1024  # 4GB
            
            # Kiểm tra GPU
            gpu = self.wmi.Win32_VideoController()[0]
            suspicious_gpu_names = ['vmware', 'virtualbox', 'parallels', 'hyper-v', 'virtual']
            hardware_checks['suspicious_gpu'] = any(name in gpu.Name.lower() for name in suspicious_gpu_names)
            
            # Kiểm tra Disk
            disk = self.wmi.Win32_DiskDrive()[0]
            hardware_checks['suspicious_disk'] = disk.Size < 100 * 1024 * 1024 * 1024  # 100GB
            
            # Kiểm tra BIOS
            bios = self.wmi.Win32_BIOS()[0]
            suspicious_bios = ['virtualbox', 'vmware', 'kvm', 'xen', 'innotek']
            hardware_checks['suspicious_bios'] = any(name in bios.Version.lower() for name in suspicious_bios)
            
            # Kiểm tra nhà sản xuất
            system = self.wmi.Win32_ComputerSystem()[0]
            suspicious_manufacturers = ['vmware', 'virtualbox', 'kvm', 'qemu', 'xen', 'innotek', 'microsoft corporation']
            hardware_checks['suspicious_manufacturer'] = any(name in system.Manufacturer.lower() for name in suspicious_manufacturers)
            
            # Tổng hợp kết quả
            suspicious_count = sum(1 for value in hardware_checks.values() if value)
            hardware_checks['is_virtual'] = suspicious_count >= 2
            
        except Exception as e:
            hardware_checks['error'] = str(e)
            
        return hardware_checks

    def _check_sandbox(self) -> Dict[str, Any]:
        """Kiểm tra các dấu hiệu của sandbox"""
        sandbox_checks = {
            'wine_detection': self._check_wine(),
            'sandboxie_detection': self._check_sandboxie(),
            'cuckoo_detection': self._check_cuckoo(),
            'threatexpert_detection': self._check_threatexpert(),
            'joebox_detection': self._check_joebox(),
            'anubis_detection': self._check_anubis(),
            'comodo_detection': self._check_comodo(),
            'sunbelt_detection': self._check_sunbelt(),
            'gfi_detection': self._check_gfi(),
            'norman_detection': self._check_norman()
        }

        # Kiểm tra tổng hợp
        sandbox_checks['is_sandbox'] = any(sandbox_checks.values())
        return sandbox_checks

    def _check_sandbox_username(self) -> bool:
        """Kiểm tra username đáng ngờ"""
        suspicious_usernames = [
            'sandbox', 'malware', 'virus', 'sample', 'test', 
            'admin', 'administrator', 'analyzer', 'analysis',
            'lab', 'maltest', 'virtest', 'santest', 'virus',
            'malware', 'test user', 'demo', 'vm'
        ]
        current_user = os.getenv('USERNAME', '').lower()
        return any(name in current_user for name in suspicious_usernames)

    def _check_sandbox_computername(self) -> bool:
        """Kiểm tra tên máy tính đáng ngờ"""
        suspicious_names = [
            'sandbox', 'malware', 'virus', 'sample', 'test',
            'analysis', 'analyzer', 'lab', 'vm', 'virtual',
            'maltest', 'virtest', 'santest'
        ]
        computer_name = platform.node().lower()
        return any(name in computer_name for name in suspicious_names)

    def _check_sandbox_path(self) -> bool:
        """Kiểm tra đường dẫn đáng ngờ"""
        suspicious_paths = [
            r'C:\sandbox',
            r'C:\virus',
            r'C:\malware',
            r'C:\sample',
            r'C:\analysis',
            r'\sandbox\\',
            r'\virus\\',
            r'\malware\\',
            r'\sample\\',
            r'\analysis\\'
        ]
        current_path = os.getcwd().lower()
        return any(path.lower() in current_path for path in suspicious_paths)

    def _check_debugger(self) -> Dict[str, bool]:
        """Kiểm tra các debugger và công cụ phân tích"""
        debug_checks = {
            'debugger_present': bool(self.kernel32.IsDebuggerPresent()),
            'remote_debugger': self._check_remote_debugger(),
            'debugging_tools': self._check_debugging_tools(),
            'ida_detection': self._check_ida(),
            'ollydbg_detection': self._check_ollydbg(),
            'x64dbg_detection': self._check_x64dbg(),
            'windbg_detection': self._check_windbg(),
            'immunity_detection': self._check_immunity()
        }

        return debug_checks

    def _check_analysis_tools(self) -> Dict[str, List[str]]:
        """Kiểm tra các công cụ phân tích malware"""
        tools = {
            'debuggers': [
                'ollydbg.exe', 'x64dbg.exe', 'x32dbg.exe', 'windbg.exe',
                'ida64.exe', 'ida.exe', 'radare2.exe', 'immunity debugger.exe'
            ],
            'network_analyzers': [
                'wireshark.exe', 'fiddler.exe', 'charles.exe', 'burpsuite.exe',
                'tcpdump.exe', 'netmon.exe'
            ],
            'process_tools': [
                'procmon.exe', 'procexp.exe', 'procexp64.exe',
                'processmonitor.exe', 'processhacker.exe'
            ],
            'sysinternals': [
                'autoruns.exe', 'filemon.exe', 'procmon.exe', 'regmon.exe',
                'process explorer.exe', 'tcpview.exe'
            ],
            'pe_tools': [
                'peid.exe', 'pestudio.exe', 'peview.exe', 'die.exe',
                'lordpe.exe', 'cff explorer.exe'
            ]
        }

        found_tools = {category: [] for category in tools}
        
        for category, tool_list in tools.items():
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in map(str.lower, tool_list):
                        found_tools[category].append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        return found_tools


    def calculate_risk_score(self) -> Dict[str, Any]:
        vm_files = self._check_vm_files()            # Thêm dấu gạch dưới
        vm_processes = self._check_vm_processes()     # Thêm dấu gạch dưới
        vm_registry = self._check_vm_registry()       # Thêm dấu gạch dưới
        analysis_tools = self._check_analysis_tools() # Thêm dấu gạch dưới
        suspicious_username = self._check_sandbox_username() # Thêm dấu gạch dưới

        risk_score = 0
        risk_factors = []

        if vm_files:
            risk_score += 20
            risk_factors.append(f"Phát hiện {len(vm_files)} files máy ảo")

        if vm_processes:
            risk_score += 25
            risk_factors.append(f"Phát hiện {len(vm_processes)} processes máy ảo")

        if vm_registry:
            risk_score += 20
            risk_factors.append(f"Phát hiện {len(vm_registry)} registry keys máy ảo")

        if analysis_tools:
            risk_score += 25
            risk_factors.append(f"Phát hiện các công cụ phân tích: {', '.join(str(tool) for tool in analysis_tools.values() if tool)}")

        if suspicious_username:
            risk_score += 10
            risk_factors.append("Phát hiện username đáng ngờ")

        risk_level = 'UNKNOWN'
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'details': {
                'vm_files': vm_files,
                'vm_processes': vm_processes,
                'vm_registry': vm_registry,
                'analysis_tools': analysis_tools,
                'suspicious_username': suspicious_username
            }
        }

    def generate_report(self) -> str:
        """Tạo báo cáo chi tiết"""
        risk_assessment = self.calculate_risk_score()
        
        report = f"""
    🔍 SANDBOX DETECTION REPORT 
    ━━━━━━━━━━━━━━━━━━━━━━━━

    ⏰ Time: {risk_assessment['timestamp']}
    💻 Hostname: {socket.gethostname()}
    🖥️ OS: {platform.platform()}

    📊 RISK ASSESSMENT:  
    - Score: {risk_assessment['score']}/100
    - Level: {risk_assessment['level']}

    🚨 RISK FACTORS:
    {chr(10).join(f'• {factor}' for factor in risk_assessment['factors'])}

    🔎 DETAILED FINDINGS:
    """
        
        details = risk_assessment['details']
        
        # Thêm điều kiện kiểm tra 'virtualization' có tồn tại trong dict không
        if 'virtualization' in details:
            if details['virtualization'].get('is_virtual', False):
                report += "\n🖥️ VIRTUALIZATION DETECTED:\n"
                for key, value in details['virtualization'].items():
                    if isinstance(value, (list, dict)):
                        if value:
                            report += f"• {key}: {len(value)} findings\n"
                    elif value:
                        report += f"• {key}: {value}\n"

        # Thêm điều kiện kiểm tra 'debugging' có tồn tại trong dict không
        if 'debugging' in details:  
            if any(details['debugging'].values()):
                report += "\n🔧 DEBUGGING DETECTED:\n"
                for key, value in details['debugging'].items():
                    if value:
                        report += f"• {key}\n"
        # Add analysis tools details
        found_tools = {k: v for k, v in details['analysis_tools'].items() if v}
        if found_tools:
            report += "\n🛠️ ANALYSIS TOOLS DETECTED:\n"
            for category, tools in found_tools.items():
                report += f"• {category}: {', '.join(tools)}\n"

        # Thêm điều kiện kiểm tra 'network' có tồn tại trong dict không
        if 'network' in details:
            if details['network'].get('suspicious_connections', []):
                report += "\n🌐 SUSPICIOUS NETWORK CONNECTIONS:\n"
                for conn in details['network']['suspicious_connections']:
                    report += f"• {conn['local_addr']} -> {conn['remote_addr']}\n"

        return report

def main() -> bool:
    detector = AdvancedEnvironmentDetector()
    risk_assessment = detector.calculate_risk_score()
    report = detector.generate_report()
    
    # Gửi báo cáo qua Telegram nếu phát hiện rủi ro
    if risk_assessment['score'] > 0:
        send_telegram_message(report, BOT_TOKEN, CHAT_ID)
    
    # Trả về True nếu phát hiện môi trường đáng ngờ
    return risk_assessment['score'] >= 50

if __name__ == "__main__":
    try:
        is_suspicious = main()
        sys.exit(1 if is_suspicious else 0)
    except Exception as e:
        error_message = f"""
⚠️ <b>Lỗi khi phân tích môi trường!</b>

💻 Thông tin:
- Hostname: {socket.gethostname()}
- Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- Error: {str(e)}
"""
        send_telegram_message(error_message, BOT_TOKEN, CHAT_ID)
        sys.exit(1)
