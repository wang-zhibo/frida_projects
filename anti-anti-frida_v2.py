#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anti-Anti-Frida Tool - 深度优化版 v2.0
增强的反检测能力，覆盖更多检测特征
"""

import lief
import sys
import random
import os
import shutil
import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import hashlib


class Colors:
    """终端颜色代码"""
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class Logger:
    """增强的日志系统"""
    def __init__(self, level=logging.INFO, log_file: Optional[str] = None):
        self.logger = logging.getLogger("AntiAntiFrida")
        self.logger.setLevel(level)
        self.logger.handlers.clear()
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, msg: str, color: str = Colors.CYAN):
        print(f"{color}[*] {msg}{Colors.RESET}")
        self.logger.info(msg)
    
    def success(self, msg: str):
        print(f"{Colors.GREEN}[✓] {msg}{Colors.RESET}")
        self.logger.info(msg)
    
    def warning(self, msg: str):
        print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
        self.logger.warning(msg)
    
    def error(self, msg: str):
        print(f"{Colors.RED}[✗] {msg}{Colors.RESET}")
        self.logger.error(msg)
    
    def debug(self, msg: str):
        print(f"{Colors.MAGENTA}[D] {msg}{Colors.RESET}")
        self.logger.debug(msg)


class EnhancedFridaPatcher:
    """增强的 Frida 补丁工具 - 深度反检测版"""
    
    # 扩展的特征字符串列表（基于实战经验）
    COMPREHENSIVE_PATCH_STRINGS = [
        # 核心 Frida 特征
        "FridaScriptEngine",
        "frida-agent",
        "frida_agent_main",
        "Frida",
        "FRIDA",
        
        # GLib 相关
        "GLib-GIO",
        "GDBusProxy",
        "GDBusConnection",
        "GDBusMessage",
        "GDBusMethodInvocation",
        
        # Gum 引擎特征
        "GumScript",
        "GumScriptBackend",
        "GumInterceptor",
        "GumInvocationListener",
        "GumInvocationContext",
        "GumStalker",
        "GumMemoryRange",
        "GumCpuContext",
        "gum_init",
        "gum_deinit",
        "gum_script",
        "gum_interceptor",
        "gum_invocation",
        
        # 线程和任务队列
        "frida-gadget",
        "frida-helper",
        "frida::Agent",
        
        # RPC 相关
        "frida_rpc",
        "_frida_",
        
        # QuickJS 相关（Frida 使用的 JS 引擎）
        "frida-qjs",
        
        # 其他特征
        "linjector",
        "zygote-agent",
    ]
    
    # 扩展的线程名列表
    COMPREHENSIVE_THREAD_NAMES = [
        ("gum-js-loop", 11),
        ("gmain", 5),
        ("gdbus", 5),
        ("pool-frida", 11),
        ("frida-agent", 12),
        ("JSC-worker", 10),  # JavaScriptCore worker
    ]
    
    # 需要修改的段名
    SECTION_NAMES_TO_PATCH = [
        ".frida",
    ]
    
    def __init__(self, 
                 input_file: str,
                 output_file: Optional[str] = None,
                 backup: bool = True,
                 dry_run: bool = False,
                 config_file: Optional[str] = None,
                 aggressive: bool = False,
                 logger: Optional[Logger] = None):
        """
        初始化增强补丁工具
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            backup: 是否备份
            dry_run: 干运行模式
            config_file: 配置文件
            aggressive: 激进模式（更多修改，可能影响稳定性）
            logger: 日志记录器
        """
        self.input_file = Path(input_file)
        self.output_file = Path(output_file) if output_file else self.input_file
        self.backup = backup
        self.dry_run = dry_run
        self.aggressive = aggressive
        self.logger = logger or Logger()
        
        self.random_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        
        # 加载配置
        self.patch_strings = self.COMPREHENSIVE_PATCH_STRINGS.copy()
        self.thread_names = self.COMPREHENSIVE_THREAD_NAMES.copy()
        
        if config_file:
            self._load_config(config_file)
        
        # 统计信息
        self.stats = {
            "symbols_patched": 0,
            "strings_patched": 0,
            "threads_patched": 0,
            "sections_patched": 0,
            "imports_patched": 0,
        }
        
        # 生成一致的随机种子（可选：基于文件哈希）
        self.random_seed = None
    
    def _load_config(self, config_file: str):
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            if 'patch_strings' in config:
                self.patch_strings = config['patch_strings']
            if 'thread_names' in config:
                self.thread_names = [(name, length) for name, length in config['thread_names']]
            if 'random_seed' in config:
                self.random_seed = config['random_seed']
            
            self.logger.success(f"配置文件加载成功: {config_file}")
        except Exception as e:
            self.logger.error(f"配置文件加载失败: {e}")
            self.logger.warning("使用默认配置")
    
    def _validate_input(self) -> bool:
        """验证输入文件"""
        if not self.input_file.exists():
            self.logger.error(f"文件不存在: {self.input_file}")
            return False
        
        if not self.input_file.is_file():
            self.logger.error(f"不是有效的文件: {self.input_file}")
            return False
        
        if not os.access(self.input_file, os.R_OK):
            self.logger.error(f"文件不可读: {self.input_file}")
            return False
        
        file_size = self.input_file.stat().st_size
        if file_size == 0:
            self.logger.error("文件为空")
            return False
        
        self.logger.info(f"文件大小: {file_size / 1024 / 1024:.2f} MB")
        
        # 计算文件哈希作为随机种子（确保每次对同一文件的修改一致）
        if self.random_seed is None:
            with open(self.input_file, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                self.random_seed = int(file_hash[:8], 16)
        
        random.seed(self.random_seed)
        self.logger.debug(f"使用随机种子: {self.random_seed}")
        
        return True
    
    def _create_backup(self) -> Optional[Path]:
        """创建备份文件"""
        if not self.backup or self.dry_run:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.input_file.with_suffix(f".bak_{timestamp}{self.input_file.suffix}")
        
        try:
            shutil.copy2(self.input_file, backup_file)
            self.logger.success(f"备份已创建: {backup_file}")
            return backup_file
        except Exception as e:
            self.logger.error(f"备份创建失败: {e}")
            return None
    
    def _random_string(self, length: int, charset: Optional[str] = None) -> str:
        """生成指定长度的随机字符串"""
        charset = charset or self.random_charset
        return "".join(random.choices(charset, k=length))
    
    def _smart_replace_string(self, original: str, strategy: str = "reverse") -> str:
        """
        智能字符串替换策略
        
        Args:
            original: 原始字符串
            strategy: 替换策略 (reverse/random/rot13/mixed)
        """
        if strategy == "reverse":
            return original[::-1]
        elif strategy == "random":
            return self._random_string(len(original))
        elif strategy == "rot13":
            return original.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
            ))
        elif strategy == "mixed":
            # 混合策略：部分反转，部分随机
            mid = len(original) // 2
            return original[:mid][::-1] + self._random_string(len(original) - mid)
        else:
            return original[::-1]
    
    def _patch_symbols(self, binary: lief.Binary) -> int:
        """修补符号表 - 增强版"""
        count = 0
        
        # 生成多个随机名称用于不同类型的符号
        frida_replace = self._random_string(5)
        gum_replace = self._random_string(3)
        g_replace = self._random_string(2)  # 替换 g_ 前缀
        
        self.logger.info(f"符号替换映射: frida->{frida_replace}, gum->{gum_replace}, g_->{g_replace}")
        
        for symbol in binary.symbols:
            original_name = symbol.name
            modified = False
            
            # 特殊处理关键符号
            if symbol.name == "frida_agent_main":
                symbol.name = "main"
                modified = True
            elif symbol.name == "frida_agent_auto_ignition":
                symbol.name = self._random_string(len(symbol.name))
                modified = True
            
            # 替换 frida 相关
            if "frida" in symbol.name.lower():
                symbol.name = symbol.name.replace("frida", frida_replace)
                symbol.name = symbol.name.replace("Frida", frida_replace.capitalize())
                symbol.name = symbol.name.replace("FRIDA", frida_replace.upper())
                modified = True
            
            # 替换 gum 相关（激进模式）
            if self.aggressive and "gum" in symbol.name.lower():
                symbol.name = symbol.name.replace("gum", gum_replace)
                symbol.name = symbol.name.replace("Gum", gum_replace.capitalize())
                symbol.name = symbol.name.replace("GUM", gum_replace.upper())
                modified = True
            
            # 替换 g_ 前缀（GLib 相关，激进模式）
            if self.aggressive and symbol.name.startswith("g_"):
                symbol.name = g_replace + "_" + symbol.name[2:]
                modified = True
            
            if modified:
                count += 1
                if self.dry_run:
                    self.logger.debug(f"[预览] 符号: {original_name} -> {symbol.name}")
        
        return count
    
    def _patch_strings(self, binary: lief.Binary) -> int:
        """修补特征字符串 - 增强版"""
        count = 0
        
        # 扫描所有可能包含字符串的段
        target_sections = [".rodata", ".data", ".dynstr"]
        
        for section in binary.sections:
            if section.name not in target_sections:
                continue
            
            for patch_str in self.patch_strings:
                addr_all = section.search_all(patch_str)
                
                for addr in addr_all:
                    # 使用智能替换策略
                    strategy = "reverse" if not self.aggressive else "mixed"
                    replaced_str = self._smart_replace_string(patch_str, strategy)
                    patch = [ord(c) for c in replaced_str]
                    offset = section.file_offset + addr
                    
                    if self.dry_run:
                        self.logger.debug(
                            f"[预览] 字符串: section={section.name} offset={hex(offset)} "
                            f"{patch_str} -> {replaced_str}"
                        )
                    else:
                        binary.patch_address(offset, patch)
                        self.logger.info(
                            f"修补字符串: section={section.name} offset={hex(offset)} "
                            f"{patch_str} -> {replaced_str}",
                            Colors.GREEN
                        )
                    
                    count += 1
        
        return count
    
    def _patch_section_names(self, binary: lief.Binary) -> int:
        """修补段名称（新增功能）"""
        count = 0
        
        if not self.aggressive:
            return 0
        
        for section in binary.sections:
            original_name = section.name
            
            # 替换包含 frida 的段名
            if "frida" in section.name.lower():
                new_name = section.name.replace("frida", self._random_string(5))
                new_name = new_name.replace("Frida", self._random_string(5))
                
                if self.dry_run:
                    self.logger.debug(f"[预览] 段名: {original_name} -> {new_name}")
                else:
                    section.name = new_name
                    self.logger.info(f"修补段名: {original_name} -> {new_name}", Colors.GREEN)
                
                count += 1
        
        return count
    
    def _patch_dynamic_entries(self, binary: lief.Binary) -> int:
        """修补动态链接表项（新增功能）"""
        count = 0
        
        if not self.aggressive:
            return 0
        
        # 某些检测会扫描动态链接的库名
        # 这里可以修改 DT_NEEDED 等项
        # 注意：修改动态链接可能导致程序无法运行，需谨慎
        
        return count
    
    def _patch_threads_binary(self, file_path: Path) -> int:
        """使用二进制替换修补线程名 - 增强版"""
        count = 0
        
        if self.dry_run:
            for thread_name, length in self.thread_names:
                random_name = self._random_string(length)
                self.logger.debug(f"[预览] 线程名: {thread_name} -> {random_name}")
            return len(self.thread_names)
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            self.logger.error(f"读取文件失败: {e}")
            return 0
        
        # 替换线程名
        for thread_name, length in self.thread_names:
            random_name = self._random_string(length)
            old_bytes = thread_name.encode('utf-8')
            new_bytes = random_name.encode('utf-8')
            
            # 替换所有出现的位置
            if old_bytes in content:
                occurrences = content.count(old_bytes)
                content = content.replace(old_bytes, new_bytes)
                count += 1
                self.logger.info(
                    f"修补线程名: {thread_name} -> {random_name} (共{occurrences}处)",
                    Colors.GREEN
                )
            else:
                self.logger.debug(f"未找到线程名: {thread_name}")
        
        # 额外的二进制特征替换（激进模式）
        if self.aggressive:
            # 替换更多二进制中的字符串特征
            additional_patterns = [
                (b"frida", self._random_string(5).encode()),
                (b"FRIDA", self._random_string(5).encode()),
                (b"/frida", ("/" + self._random_string(5)).encode()),
            ]
            
            for old_pattern, new_pattern in additional_patterns:
                if old_pattern in content:
                    occurrences = content.count(old_pattern)
                    content = content.replace(old_pattern, new_pattern)
                    count += occurrences
                    self.logger.info(
                        f"修补二进制特征: {old_pattern.decode()} -> {new_pattern.decode()} "
                        f"(共{occurrences}处)",
                        Colors.GREEN
                    )
        
        try:
            with open(file_path, 'wb') as f:
                f.write(content)
        except Exception as e:
            self.logger.error(f"写入文件失败: {e}")
            return 0
        
        return count
    
    def patch(self) -> bool:
        """执行完整的补丁流程"""
        try:
            if not self._validate_input():
                return False
            
            mode_str = "[干运行模式]" if self.dry_run else ""
            aggressive_str = "[激进模式]" if self.aggressive else "[标准模式]"
            self.logger.info(f"{mode_str}{aggressive_str} 开始修补: {self.input_file}")
            
            # 创建备份
            if not self.dry_run and self.backup and self.input_file == self.output_file:
                backup_file = self._create_backup()
                if backup_file is None and self.backup:
                    self.logger.warning("备份失败，继续执行可能有风险")
                    response = input("是否继续？(y/N): ")
                    if response.lower() != 'y':
                        self.logger.warning("用户取消操作")
                        return False
            
            # 如果输出文件不同，先复制
            if self.input_file != self.output_file and not self.dry_run:
                shutil.copy2(self.input_file, self.output_file)
                self.logger.info(f"复制文件: {self.input_file} -> {self.output_file}")
            
            # 解析二进制文件
            self.logger.info("解析 ELF 文件...")
            binary = lief.parse(str(self.input_file))
            
            if not binary:
                self.logger.error("不是有效的 ELF 文件")
                return False
            
            # 显示二进制信息
            self.logger.info(f"架构: {binary.header.machine_type}")
            self.logger.info(f"类型: {binary.header.file_type}")
            
            # === 步骤 1: 修补符号表 ===
            self.logger.info("\n" + "=" * 60)
            self.logger.info("步骤 1: 修补符号表")
            self.logger.info("=" * 60)
            self.stats["symbols_patched"] = self._patch_symbols(binary)
            self.logger.success(f"符号修补完成: {self.stats['symbols_patched']} 个符号")
            
            # === 步骤 2: 修补特征字符串 ===
            self.logger.info("\n" + "=" * 60)
            self.logger.info("步骤 2: 修补特征字符串")
            self.logger.info("=" * 60)
            self.stats["strings_patched"] = self._patch_strings(binary)
            self.logger.success(f"字符串修补完成: {self.stats['strings_patched']} 处修改")
            
            # === 步骤 3: 修补段名称（激进模式）===
            if self.aggressive:
                self.logger.info("\n" + "=" * 60)
                self.logger.info("步骤 3: 修补段名称 [激进模式]")
                self.logger.info("=" * 60)
                self.stats["sections_patched"] = self._patch_section_names(binary)
                self.logger.success(f"段名修补完成: {self.stats['sections_patched']} 个段")
            
            # 写入修改
            if not self.dry_run:
                self.logger.info("\n写入修改到文件...")
                binary.write(str(self.output_file))
                self.logger.success("ELF 文件写入完成")
            
            # === 步骤 4: 修补线程名称和二进制特征 ===
            self.logger.info("\n" + "=" * 60)
            self.logger.info("步骤 4: 修补线程名称和二进制特征")
            self.logger.info("=" * 60)
            self.stats["threads_patched"] = self._patch_threads_binary(self.output_file)
            self.logger.success(f"二进制修补完成: {self.stats['threads_patched']} 处修改")
            
            # 显示统计信息
            self._print_stats()
            
            # 显示建议
            self._print_recommendations()
            
            if self.dry_run:
                self.logger.info(f"\n{Colors.YELLOW}[干运行模式] 未实际修改文件{Colors.RESET}")
            else:
                self.logger.success(f"\n✨ 修补完成！输出文件: {self.output_file}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"修补过程出错: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def _print_stats(self):
        """打印统计信息"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("修补统计", Colors.BOLD)
        self.logger.info("=" * 60)
        self.logger.info(f"符号修补数量:     {self.stats['symbols_patched']}", Colors.CYAN)
        self.logger.info(f"字符串修补数量:   {self.stats['strings_patched']}", Colors.CYAN)
        self.logger.info(f"段名修补数量:     {self.stats['sections_patched']}", Colors.CYAN)
        self.logger.info(f"二进制修补数量:   {self.stats['threads_patched']}", Colors.CYAN)
        self.logger.info(
            f"总修改数量:       {sum(self.stats.values())}",
            Colors.GREEN
        )
        self.logger.info("=" * 60)
    
    def _print_recommendations(self):
        """打印使用建议"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("使用建议", Colors.YELLOW)
        self.logger.info("=" * 60)
        self.logger.info("1. 修改 frida-server 的默认端口（避免 27042 端口检测）", Colors.YELLOW)
        self.logger.info("2. 使用随机的进程名启动（避免进程名检测）", Colors.YELLOW)
        self.logger.info("3. 配合 hide_frida_linjector 等工具使用", Colors.YELLOW)
        self.logger.info("4. 测试修补后的文件是否正常工作", Colors.YELLOW)
        if not self.aggressive:
            self.logger.info("5. 如需更强的混淆，使用 --aggressive 模式", Colors.YELLOW)
        self.logger.info("=" * 60)


def create_enhanced_config(output_file: str = "anti-frida-enhanced-config.json"):
    """创建增强配置文件"""
    config = {
        "patch_strings": EnhancedFridaPatcher.COMPREHENSIVE_PATCH_STRINGS,
        "thread_names": EnhancedFridaPatcher.COMPREHENSIVE_THREAD_NAMES,
        "random_seed": random.randint(1000, 9999),
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"{Colors.GREEN}[✓] 增强配置文件已创建: {output_file}{Colors.RESET}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="Anti-Anti-Frida Tool - 深度反检测优化版 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s frida-server                           # 标准模式修补
  %(prog)s frida-server --aggressive              # 激进模式（更多修改）
  %(prog)s frida-server -o patched                # 输出到新文件
  %(prog)s frida-server --dry-run -v              # 预览详细修改
  %(prog)s frida-server -c config.json            # 使用自定义配置
  %(prog)s --create-config                        # 生成配置文件
  %(prog)s frida-server --no-backup               # 不创建备份（慎用）
  
注意:
  - 标准模式：修改核心特征，稳定性高
  - 激进模式：修改更多特征，可能影响稳定性，建议充分测试
  - 建议先使用 --dry-run 预览修改
        """
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        help='输入的 Frida 二进制文件路径'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        help='输出文件路径（默认覆盖原文件）'
    )
    
    parser.add_argument(
        '--no-backup',
        dest='backup',
        action='store_false',
        help='不创建备份文件'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='干运行模式：预览修改但不实际执行'
    )
    
    parser.add_argument(
        '-c', '--config',
        dest='config_file',
        help='自定义配置文件路径（JSON 格式）'
    )
    
    parser.add_argument(
        '--create-config',
        action='store_true',
        help='创建增强配置文件并退出'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='详细输出（调试模式）'
    )
    
    parser.add_argument(
        '--log-file',
        dest='log_file',
        help='保存日志到文件'
    )
    
    parser.add_argument(
        '-a', '--aggressive',
        action='store_true',
        help='激进模式：修改更多特征（可能影响稳定性）'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 2.0.0 (深度优化版)'
    )
    
    args = parser.parse_args()
    
    # 创建配置文件
    if args.create_config:
        create_enhanced_config()
        return 0
    
    # 检查必需参数
    if not args.input_file:
        parser.print_help()
        return 1
    
    # 设置日志级别
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = Logger(level=log_level, log_file=args.log_file)
    
    # 显示欢迎信息
    logger.info("=" * 60, Colors.BOLD)
    logger.info("Anti-Anti-Frida Tool - 深度优化版 v2.0", Colors.BOLD)
    logger.info("=" * 60, Colors.BOLD)
    
    if args.aggressive:
        logger.warning("⚠️  激进模式已启用，可能影响程序稳定性，请充分测试！")
    
    # 创建补丁工具并执行
    patcher = EnhancedFridaPatcher(
        input_file=args.input_file,
        output_file=args.output_file,
        backup=args.backup,
        dry_run=args.dry_run,
        config_file=args.config_file,
        aggressive=args.aggressive,
        logger=logger
    )
    
    success = patcher.patch()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

