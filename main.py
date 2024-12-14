#!/usr/bin/env python3

import os
import sys
import platform
import random
import subprocess
import socket
import threading
import time
import json
import base64
import hashlib
import uuid

try:
    from colorama import init, Fore, Back, Style
    import requests
    import scapy.all as scapy
    import paramiko
    import psutil
except ImportError:
    print("Required dependencies not found. Please install them first.")
    sys.exit(1)

class NzBoysUltimateTool:
    def __init__(self):
        # Advanced color initialization
        init(autoreset=True)
        
        # Color palette
        self.COLORS = {
            'HEADER': Fore.MAGENTA + Style.BRIGHT,
            'SUCCESS': Fore.GREEN + Style.BRIGHT,
            'WARNING': Fore.YELLOW + Style.BRIGHT,
            'ERROR': Fore.RED + Style.BRIGHT,
            'INFO': Fore.CYAN + Style.BRIGHT,
            'RESET': Style.RESET_ALL
        }
        
        # Custom logo with color gradient
        self.logo = f'''{self.COLORS['HEADER']}
 _   _  ______   ____                  
| \\ | ||___  / |  _ \\                 
|  \\| |   / /  | |_) | ___  _ __  ___ 
| . ` |  / /   |  _ < / _ \\| '_ \\/ __|
| |\\  | / /_   | |_) | (_) | | | \\__ \\
|_| \\_|/___|   |____/ \\___/|_| |_|___/
{self.COLORS['INFO']}NzBoys CYBERSECURITY TOOLKIT{self.COLORS['RESET']}
        '''
        
        # Advanced system configuration
        self.config = {
            'version': '2.0',
            'last_update': '2024-12-14',
            'debug_mode': False
        }
        
        # Exploit and vulnerability database
        self.vulnerability_db = {}
        self.exploit_db = {}
    
    def colored_print(self, message, color_key='INFO', style=Style.BRIGHT):
        """Enhanced colored printing with multiple options"""
        color = self.COLORS.get(color_key, self.COLORS['INFO'])
        print(f"{color}{style}{message}{self.COLORS['RESET']}")
    
    def advanced_system_check(self):
        """Comprehensive system compatibility and security check"""
        self.colored_print("Performing Advanced System Compatibility Check...", 'INFO')
        
        checks = [
            ('Operating System', platform.system()),
            ('Distribution', platform.linux_distribution()[0]),
            ('Python Version', platform.python_version()),
            ('Processor', platform.processor()),
            ('Machine Architecture', platform.machine())
        ]
        
        for label, value in checks:
            print(f"{self.COLORS['SUCCESS']}[✓] {label}: {value}{self.COLORS['RESET']}")
        
        # Check for necessary permissions
        if os.geteuid() != 0:
            self.colored_print("⚠️ Root access recommended for full functionality!", 'WARNING')
    
    def network_intelligence_module(self):
        """Advanced Network Intelligence and Mapping"""
        self.colored_print("Network Intelligence Module", 'HEADER')
        
        target = input(f"{self.COLORS['INFO']}Enter target network/IP: {self.COLORS['RESET']}")
        
        try:
            # Advanced network scanning with multiple techniques
            def tcp_scan():
                self.colored_print("Performing TCP SYN Scan...", 'INFO')
                ans, unans = scapy.sr(scapy.IP(dst=target)/scapy.TCP(flags="S"), timeout=2)
                tcp_ports = [port.sport for sent, port in ans if port[scapy.TCP].flags == "SA"]
                return tcp_ports
            
            def udp_scan():
                self.colored_print("Performing UDP Scan...", 'INFO')
                ans, unans = scapy.sr(scapy.IP(dst=target)/scapy.UDP(), timeout=2)
                udp_ports = [port.sport for sent, port in ans]
                return udp_ports
            
            # Threaded scanning for efficiency
            tcp_thread = threading.Thread(target=tcp_scan)
            udp_thread = threading.Thread(target=udp_scan)
            
            tcp_thread.start()
            udp_thread.start()
            
            tcp_thread.join()
            udp_thread.join()
        
        except Exception as e:
            self.colored_print(f"Network scanning error: {e}", 'ERROR')
    
    def android_security_analyzer(self):
        """Comprehensive Android Security Analysis"""
        self.colored_print("Android Security Analyzer", 'HEADER')
        
        security_checks = {
            'Device Rooting Status': self.check_root_status,
            'ADB Debugging': self.check_adb_debugging,
            'USB Debugging': self.check_usb_debugging,
            'Unknown Sources Installation': self.check_unknown_sources
        }
        
        results = {}
        for check_name, check_func in security_checks.items():
            try:
                result = check_func()
                results[check_name] = result
                status = self.COLORS['SUCCESS'] + "SECURE" if not result else self.COLORS['ERROR'] + "VULNERABLE"
                print(f"{check_name}: {status}{self.COLORS['RESET']}")
            except Exception as e:
                self.colored_print(f"Error in {check_name}: {e}", 'WARNING')
        
        return results
    
    def cryptographic_toolkit(self):
        """Advanced Cryptographic Utilities"""
        while True:
            self.colored_print("\nCryptographic Toolkit", 'HEADER')
            print("1. Hash Generator")
            print("2. Base64 Encoder/Decoder")
            print("3. UUID Generator")
            print("4. Return to Main Menu")
            
            choice = input(f"{self.COLORS['INFO']}Choose an option: {self.COLORS['RESET']}")
            
            if choice == '1':
                text = input("Enter text to hash: ")
                algorithms = ['md5', 'sha1', 'sha256', 'sha512']
                for algo in algorithms:
                    hash_obj = hashlib.new(algo)
                    hash_obj.update(text.encode())
                    print(f"{algo.upper()}: {hash_obj.hexdigest()}")
            
            elif choice == '2':
                mode = input("Encode or Decode? (e/d): ")
                text = input("Enter text: ")
                
                if mode.lower() == 'e':
                    encoded = base64.b64encode(text.encode()).decode()
                    self.colored_print(f"Encoded: {encoded}", 'SUCCESS')
                else:
                    try:
                        decoded = base64.b64decode(text.encode()).decode()
                        self.colored_print(f"Decoded: {decoded}", 'SUCCESS')
                    except:
                        self.colored_print("Invalid Base64 string", 'ERROR')
            
            elif choice == '3':
                generated_uuid = str(uuid.uuid4())
                self.colored_print(f"Generated UUID: {generated_uuid}", 'INFO')
            
            elif choice == '4':
                break
    
    def device_performance_monitor(self):
        """Real-time Device Performance Monitoring"""
        self.colored_print("Device Performance Monitor", 'HEADER')
        
        def monitor_resources():
            while True:
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                os.system('clear')
                print(f"{self.COLORS['INFO']}== Device Performance ==")
                print(f"CPU Usage: {cpu_usage}%")
                print(f"Memory: {memory.percent}% Used")
                print(f"Disk: {disk.percent}% Used")
                
                time.sleep(2)
        
        monitor_thread = threading.Thread(target=monitor_resources)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        input(f"{self.COLORS['WARNING']}Press Enter to stop monitoring...{self.COLORS['RESET']}")
    
    def main_menu(self):
        """Advanced Main Menu with Color-Coded Options"""
        while True:
            self.colored_print("\n=== NZ BOYS ULTIMATE TOOLKIT ===", 'HEADER')
            menu_options = [
                "System Intelligence",
                "Network Mapping",
                "Android Security Analyzer",
                "Cryptographic Toolkit",
                "Device Performance Monitor",
                "Exit"
            ]
            
            for idx, option in enumerate(menu_options, 1):
                color = self.COLORS['SUCCESS'] if idx % 2 == 0 else self.COLORS['INFO']
                print(f"{color}{idx}. {option}{self.COLORS['RESET']}")
            
            choice = input(f"{self.COLORS['WARNING']}Select an option: {self.COLORS['RESET']}")
            
            actions = {
                '1': self.advanced_system_check,
                '2': self.network_intelligence_module,
                '3': self.android_security_analyzer,
                '4': self.cryptographic_toolkit,
                '5': self.device_performance_monitor
            }
            
            action = actions.get(choice)
            if action:
                action()
            elif choice == '6':
                break
            else:
                self.colored_print("Invalid option. Try again.", 'ERROR')
    
    def run(self):
        """Main execution method"""
        print(self.logo)
        self.main_menu()

if __name__ == "__main__":
    try:
        toolkit = NzBoysUltimateTool()
        toolkit.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Operation cancelled.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")