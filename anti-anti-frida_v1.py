#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anti-Anti-Frida Tool - 优化增强版
用于修改 Frida 特征，绕过常见的 Frida 检测机制
"""

import lief
import sys
import random
import os
import shutil
import subprocess
import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime


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
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器（可选）
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


class FridaPatcher:
    """Frida Agent 补丁工具类"""
    
    # 默认特征字符串配置
    DEFAULT_PATCH_STRINGS = [
        "FridaScriptEngine",
        "GLib-GIO",
        "GDBusProxy", 
        "GumScript",
        "frida-agent",
        "Frida",
        "FRIDA",
    ]
    
    DEFAULT_THREAD_NAMES = [
        ("gum-js-loop", 11),
        ("gmain", 5),
        ("gdbus", 5),
        ("pool-frida", 11),
    ]
    
    def __init__(self, 
                 input_file: str,
                 output_file: Optional[str] = None,
                 backup: bool = True,
                 dry_run: bool = False,
                 config_file: Optional[str] = None,
                 logger: Optional[Logger] = None):
        """
        初始化补丁工具
        
        Args:
            input_file: 输入的 Frida Agent 文件路径
            output_file: 输出文件路径（None 则覆盖原文件）
            backup: 是否创建备份
            dry_run: 是否为干运行模式（仅预览不修改）
            config_file: 配置文件路径
            logger: 日志记录器
        """
        self.input_file = Path(input_file)
        self.output_file = Path(output_file) if output_file else self.input_file
        self.backup = backup
        self.dry_run = dry_run
        self.logger = logger or Logger()
        
        # 随机字符集
        self.random_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        
        # 加载配置
        self.patch_strings = self.DEFAULT_PATCH_STRINGS.copy()
        self.thread_names = self.DEFAULT_THREAD_NAMES.copy()
        
        if config_file:
            self._load_config(config_file)
        
        # 统计信息
        self.stats = {
            "symbols_patched": 0,
            "strings_patched": 0,
            "threads_patched": 0,
        }
    
    def _load_config(self, config_file: str):
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            if 'patch_strings' in config:
                self.patch_strings = config['patch_strings']
            if 'thread_names' in config:
                self.thread_names = [(name, length) for name, length in config['thread_names']]
            
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
        
        # 检查文件大小
        file_size = self.input_file.stat().st_size
        if file_size == 0:
            self.logger.error("文件为空")
            return False
        
        self.logger.info(f"文件大小: {file_size / 1024 / 1024:.2f} MB")
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
    
    def _random_string(self, length: int) -> str:
        """生成指定长度的随机字符串"""
        return "".join(random.choices(self.random_charset, k=length))
    
    def _patch_symbols(self, binary: lief.Binary) -> int:
        """修补符号表"""
        count = 0
        random_name = self._random_string(5)
        
        self.logger.info(f"将 'frida' 替换为 '{random_name}'")
        
        for symbol in binary.symbols:
            original_name = symbol.name
            modified = False
            
            # 特殊处理 frida_agent_main
            if symbol.name == "frida_agent_main":
                symbol.name = "main"
                modified = True
            
            # 替换包含 frida 的符号
            if "frida" in symbol.name:
                symbol.name = symbol.name.replace("frida", random_name)
                modified = True
            
            # 替换包含 FRIDA 的符号
            if "FRIDA" in symbol.name:
                symbol.name = symbol.name.replace("FRIDA", random_name.upper())
                modified = True
            
            if modified:
                count += 1
                if self.dry_run:
                    self.logger.debug(f"[预览] 符号: {original_name} -> {symbol.name}")
        
        return count
    
    def _patch_strings(self, binary: lief.Binary) -> int:
        """修补特征字符串"""
        count = 0
        
        for section in binary.sections:
            if section.name != ".rodata":
                continue
            
            for patch_str in self.patch_strings:
                addr_all = section.search_all(patch_str)
                
                for addr in addr_all:
                    # 反转字符串
                    reversed_str = patch_str[::-1]
                    patch = [ord(c) for c in reversed_str]
                    offset = section.file_offset + addr
                    
                    if self.dry_run:
                        self.logger.debug(
                            f"[预览] 字符串: offset={hex(offset)} "
                            f"{patch_str} -> {reversed_str}"
                        )
                    else:
                        binary.patch_address(offset, patch)
                        self.logger.info(
                            f"修补字符串: offset={hex(offset)} "
                            f"{patch_str} -> {reversed_str}",
                            Colors.GREEN
                        )
                    
                    count += 1
        
        return count
    
    def _patch_threads_sed(self, file_path: Path) -> int:
        """使用二进制替换修补线程名（兼容性更好的实现）"""
        count = 0
        
        if self.dry_run:
            for thread_name, length in self.thread_names:
                random_name = self._random_string(length)
                self.logger.debug(f"[预览] 线程名: {thread_name} -> {random_name}")
            return len(self.thread_names)
        
        # 读取文件内容
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            self.logger.error(f"读取文件失败: {e}")
            return 0
        
        # 逐个替换线程名
        for thread_name, length in self.thread_names:
            random_name = self._random_string(length)
            old_bytes = thread_name.encode('utf-8')
            new_bytes = random_name.encode('utf-8')
            
            if old_bytes in content:
                content = content.replace(old_bytes, new_bytes)
                count += 1
                self.logger.info(
                    f"修补线程名: {thread_name} -> {random_name}",
                    Colors.GREEN
                )
            else:
                self.logger.warning(f"未找到线程名: {thread_name}")
        
        # 写回文件
        try:
            with open(file_path, 'wb') as f:
                f.write(content)
        except Exception as e:
            self.logger.error(f"写入文件失败: {e}")
            return 0
        
        return count
    
    def patch(self) -> bool:
        """执行补丁操作"""
        try:
            # 验证输入
            if not self._validate_input():
                return False
            
            mode_str = "[干运行模式]" if self.dry_run else ""
            self.logger.info(f"{mode_str} 开始修补 Frida Agent: {self.input_file}")
            
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
            
            # 修补符号
            self.logger.info("=" * 60)
            self.logger.info("步骤 1: 修补符号表")
            self.logger.info("=" * 60)
            self.stats["symbols_patched"] = self._patch_symbols(binary)
            self.logger.success(f"符号修补完成: {self.stats['symbols_patched']} 个符号")
            
            # 修补字符串
            self.logger.info("=" * 60)
            self.logger.info("步骤 2: 修补特征字符串")
            self.logger.info("=" * 60)
            self.stats["strings_patched"] = self._patch_strings(binary)
            self.logger.success(f"字符串修补完成: {self.stats['strings_patched']} 处修改")
            
            # 写入修改
            if not self.dry_run:
                self.logger.info("写入修改到文件...")
                binary.write(str(self.output_file))
            
            # 修补线程名
            self.logger.info("=" * 60)
            self.logger.info("步骤 3: 修补线程名称")
            self.logger.info("=" * 60)
            self.stats["threads_patched"] = self._patch_threads_sed(self.output_file)
            self.logger.success(f"线程名修补完成: {self.stats['threads_patched']} 个线程")
            
            # 显示统计信息
            self._print_stats()
            
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
        self.logger.info(f"符号修补数量:   {self.stats['symbols_patched']}", Colors.CYAN)
        self.logger.info(f"字符串修补数量: {self.stats['strings_patched']}", Colors.CYAN)
        self.logger.info(f"线程名修补数量: {self.stats['threads_patched']}", Colors.CYAN)
        self.logger.info(
            f"总修改数量:     {sum(self.stats.values())}",
            Colors.GREEN
        )
        self.logger.info("=" * 60)


def create_default_config(output_file: str = "anti-frida-config.json"):
    """创建默认配置文件"""
    config = {
        "patch_strings": FridaPatcher.DEFAULT_PATCH_STRINGS,
        "thread_names": FridaPatcher.DEFAULT_THREAD_NAMES,
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"{Colors.GREEN}[✓] 默认配置文件已创建: {output_file}{Colors.RESET}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="Anti-Anti-Frida Tool - 修改 Frida 二进制文件特征以绕过检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s frida-server                          # 直接修改文件（会备份）
  %(prog)s frida-server -o patched.so            # 输出到新文件
  %(prog)s frida-server --no-backup              # 不创建备份
  %(prog)s frida-server --dry-run                # 预览修改而不实际执行
  %(prog)s frida-server -c custom.json           # 使用自定义配置
  %(prog)s --create-config                       # 生成默认配置文件
  %(prog)s frida-server -v                       # 详细输出
  %(prog)s frida-server --log-file patch.log     # 保存日志到文件
        """
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        help='输入的 Frida 二进制文件路径 (例如: frida-server)'
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
        help='创建默认配置文件并退出'
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
        '--version',
        action='version',
        version='%(prog)s 2.0.0 (优化增强版)'
    )
    
    args = parser.parse_args()
    
    # 创建配置文件
    if args.create_config:
        create_default_config()
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
    logger.info("Anti-Anti-Frida Tool - 优化增强版 v2.0.0", Colors.BOLD)
    logger.info("=" * 60, Colors.BOLD)
    
    # 创建补丁工具并执行
    patcher = FridaPatcher(
        input_file=args.input_file,
        output_file=args.output_file,
        backup=args.backup,
        dry_run=args.dry_run,
        config_file=args.config_file,
        logger=logger
    )
    
    success = patcher.patch()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

