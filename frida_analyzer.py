#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 特征分析工具
用于分析 Frida 二进制文件中的检测特征
"""

import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Set


class Colors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[1;36m'
    RESET = '\033[0m'


class FridaAnalyzer:
    """Frida 特征分析器"""
    
    # 敏感特征列表
    SENSITIVE_PATTERNS = [
        # 核心特征
        "frida", "FRIDA", "Frida",
        
        # Gum 引擎
        "gum", "Gum", "GUM",
        "GumScript", "GumInterceptor", "GumStalker",
        "GumInvocation",
        
        # GLib/GDBus
        "GDBus", "GLib",
        
        # 其他
        "linjector",
    ]
    
    THREAD_PATTERNS = [
        "gum-js-loop",
        "gmain",
        "gdbus",
        "pool-frida",
    ]
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.findings = {
            "symbols": [],
            "strings": [],
            "threads": [],
        }
    
    def analyze(self):
        """执行完整分析"""
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}Frida 特征分析工具{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        print(f"分析文件: {self.file_path}")
        
        if not self.file_path.exists():
            print(f"{Colors.RED}[✗] 文件不存在{Colors.RESET}")
            return False
        
        print()
        self._analyze_symbols()
        print()
        self._analyze_strings()
        print()
        self._print_summary()
        
        return True
    
    def _analyze_symbols(self):
        """分析符号表"""
        print(f"{Colors.YELLOW}[*] 分析符号表...{Colors.RESET}")
        
        try:
            result = subprocess.run(
                ["readelf", "-s", str(self.file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                print(f"{Colors.RED}[✗] readelf 执行失败{Colors.RESET}")
                return
            
            lines = result.stdout.split('\n')
            found_count = 0
            
            for line in lines:
                for pattern in self.SENSITIVE_PATTERNS:
                    if pattern.lower() in line.lower():
                        self.findings["symbols"].append(line.strip())
                        found_count += 1
                        break
            
            if found_count > 0:
                print(f"{Colors.RED}[!] 发现 {found_count} 个敏感符号{Colors.RESET}")
                # 显示前 5 个
                for symbol in self.findings["symbols"][:5]:
                    print(f"    {symbol}")
                if len(self.findings["symbols"]) > 5:
                    print(f"    ... 还有 {len(self.findings['symbols']) - 5} 个")
            else:
                print(f"{Colors.GREEN}[✓] 未发现敏感符号{Colors.RESET}")
                
        except FileNotFoundError:
            print(f"{Colors.YELLOW}[!] readelf 未安装，跳过符号分析{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] 符号分析出错: {e}{Colors.RESET}")
    
    def _analyze_strings(self):
        """分析字符串"""
        print(f"{Colors.YELLOW}[*] 分析字符串特征...{Colors.RESET}")
        
        try:
            result = subprocess.run(
                ["strings", str(self.file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"{Colors.RED}[✗] strings 执行失败{Colors.RESET}")
                return
            
            lines = result.stdout.split('\n')
            string_findings = set()
            thread_findings = set()
            
            for line in lines:
                # 检查敏感字符串
                for pattern in self.SENSITIVE_PATTERNS:
                    if pattern in line:
                        string_findings.add(line.strip())
                        break
                
                # 检查线程名
                for pattern in self.THREAD_PATTERNS:
                    if pattern in line:
                        thread_findings.add(line.strip())
            
            self.findings["strings"] = list(string_findings)
            self.findings["threads"] = list(thread_findings)
            
            # 报告字符串
            if string_findings:
                print(f"{Colors.RED}[!] 发现 {len(string_findings)} 个敏感字符串{Colors.RESET}")
                for s in list(string_findings)[:10]:
                    print(f"    {s}")
                if len(string_findings) > 10:
                    print(f"    ... 还有 {len(string_findings) - 10} 个")
            else:
                print(f"{Colors.GREEN}[✓] 未发现敏感字符串{Colors.RESET}")
            
            # 报告线程名
            print()
            if thread_findings:
                print(f"{Colors.RED}[!] 发现 {len(thread_findings)} 个线程名特征{Colors.RESET}")
                for t in thread_findings:
                    print(f"    {t}")
            else:
                print(f"{Colors.GREEN}[✓] 未发现线程名特征{Colors.RESET}")
                
        except FileNotFoundError:
            print(f"{Colors.YELLOW}[!] strings 未安装，跳过字符串分析{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] 字符串分析出错: {e}{Colors.RESET}")
    
    def _print_summary(self):
        """打印摘要"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}分析摘要{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        total = (len(self.findings["symbols"]) + 
                len(self.findings["strings"]) + 
                len(self.findings["threads"]))
        
        print(f"符号表敏感项:   {len(self.findings['symbols'])}")
        print(f"字符串敏感项:   {len(self.findings['strings'])}")
        print(f"线程名敏感项:   {len(self.findings['threads'])}")
        print(f"总计:          {total}")
        
        print()
        if total > 0:
            print(f"{Colors.RED}[!] 建议: 该文件包含 Frida 特征，容易被检测{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] 请使用 anti-anti-frida 工具进行修补{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[✓] 该文件已清除主要 Frida 特征{Colors.RESET}")
        
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")


def compare_files(file1: str, file2: str):
    """对比两个文件"""
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}对比分析{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    print(f"原始文件: {file1}")
    analyzer1 = FridaAnalyzer(file1)
    analyzer1.analyze()
    
    print(f"\n\n修补文件: {file2}")
    analyzer2 = FridaAnalyzer(file2)
    analyzer2.analyze()
    
    # 计算改进
    before_total = (len(analyzer1.findings["symbols"]) + 
                   len(analyzer1.findings["strings"]) + 
                   len(analyzer1.findings["threads"]))
    
    after_total = (len(analyzer2.findings["symbols"]) + 
                  len(analyzer2.findings["strings"]) + 
                  len(analyzer2.findings["threads"]))
    
    removed = before_total - after_total
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}改进效果{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"修补前特征数: {before_total}")
    print(f"修补后特征数: {after_total}")
    print(f"清除特征数:   {removed}")
    
    if removed > 0:
        percentage = (removed / before_total * 100) if before_total > 0 else 0
        print(f"清除比例:     {percentage:.1f}%")
        print(f"{Colors.GREEN}[✓] 修补有效{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] 未发现明显改进{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")


def main():
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <file>                 # 分析单个文件")
        print(f"  {sys.argv[0]} <file1> <file2>        # 对比两个文件")
        return 1
    
    if len(sys.argv) == 2:
        # 分析单个文件
        analyzer = FridaAnalyzer(sys.argv[1])
        analyzer.analyze()
    elif len(sys.argv) == 3:
        # 对比两个文件
        compare_files(sys.argv[1], sys.argv[2])
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

