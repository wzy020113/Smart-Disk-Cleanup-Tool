#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能磁盘清理工具 - 像 WizTree 一样分析磁盘空间，但更智能地告诉你哪些能删
"""

import os
import sys
import shutil
import threading
import time
import json
import hashlib
import fnmatch
import platform
from pathlib import Path
from datetime import datetime, timedelta
from tkinter import (
    Tk, ttk, Frame, Label, Button, Entry, Checkbutton,
    BooleanVar, StringVar, IntVar, messagebox, filedialog,
    scrolledtext, Menu, Toplevel, Text, DISABLED, NORMAL, END, WORD
)
from tkinter.ttk import Progressbar

# 防止 Windows 下控制台窗口闪烁
if platform.system() == "Windows":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW("智能磁盘清理工具")
    except:
        pass

# ============================================================
# 安全分类规则引擎
# ============================================================

# 安全删除的文件/目录名模式（完全匹配）
SAFE_NAMES = {
    # Windows 临时文件
    "tmp", "temp", "_tmp", "_temp",
    # 缓存
    "cache", "_cache", "__cache__",
    # 浏览器缓存
    "Cache", "CACHE", "cached", "cacheddata",
    "Temporary Internet Files", "INetCache",
    "Chrome", "chromium", "Chromium",
    "WebCache", "WebCacheV01.dat",
    # 缩略图
    "Thumbs.db", "thumbs.db", "Thumbs.db:encryptable",
    # 回收站
    "$Recycle.Bin", "Recycle Bin", "回收站",
    # 日志
    "Logs", "logs", "LOG", "log",
    # Python 缓存
    "__pycache__",
    # Node
    "node_modules", "bower_components",
    # 包管理器缓存
    ".npm", ".yarn", ".pnpm", ".cargo",
    # VS Code
    ".vscode", ".vscode-server",
    # JetBrains
    ".idea", ".IntelliJIdea*",
    # 其他 IDE
    ".eclipse", ".settings",
    # 系统临时
    "Temp", "TEMP", "tmp",
    "Windows Temp", "WinTemp",
    # 预取
    "Prefetch", "prefetch",
    # 崩溃转储
    "CrashDumps", "dumps", "DumpFiles",
    # 备份
    "Backup", "backup", "old", "OLD",
    # 下载缓存
    "downloads", "Downloads",
    ".git",  # git 仓库（风险中等，但可重新clone）
    ".svn",
    # macOS
    ".Trash", ".Trashes", ".Spotlight-V100",
    # Office 缓存
    "~$", "~*",
    # 微信/QQ 缓存
    "WeChat Files", "QQ Files",
    "WeChatCache", "QQCache",
    # 系统更新缓存
    "SoftwareDistribution", "softwaredistribution",
    # MSI 安装缓存
    "Installer", "{*}",  # MSI GUID 目录
    # 回收站内部
    "RECYCLER", "RECYCLED",
}

# 安全删除的文件扩展名
SAFE_EXTENSIONS = {
    # 临时文件
    ".tmp", ".temp", ".~tmp", ".~", ".$$$",
    # 日志
    ".log", ".lo_", ".lg_",
    # 崩溃转储
    ".dmp", ".hdmp", ".mdmp", ".minidump", ".dump",
    # 缓存
    ".cache", ".blob", ".dat",  # 谨慎：.dat 可能重要
    # 备份（部分）
    ".bak", ".old", ".backup", ".bkp",
    # Python 字节码
    ".pyc", ".pyo", ".pyd",
    # 缩略图/索引
    ".db",  # 谨慎处理
    # 安装缓存
    ".msi", ".msp",  # 安装后可删除
    # 浏览器缓存
    ".fcz", ".fth",  # Flash 缓存
    # 临时生成文件
    ".generated", ".g.dart",
    # 构建产物
    ".o", ".obj",
    # 编译中间文件
    ".class",  # Java 字节码
    ".ilk", ".pdb",  # 编译中间文件
    # 日志压缩
    ".log.gz", ".log.zip", ".log.1", ".log.2",
    # 回收站文件
    ".trash",
    # 缩略图
    ".thumbnail",
}

# 绝不能删除的目录（系统保护）
SYSTEM_PROTECTED_DIRS = {
    "Windows", "System32", "System", "SysWOW64",
    "Program Files", "Program Files (x86)",
    "ProgramData", "All Users",
    "AppData",  # 整体不删，但子目录可以清理
    "Boot", "boot",
    "System Volume Information",
    "Config.Msi",
    "WindowsApps",
    "WinSxS",
    "Microsoft.NET",
    "assembly",
    "drivers", "DRIVERS",
    "etc", "ETC",
}

# 绝不能删除的文件扩展名（系统文件）
SYSTEM_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl",
    ".com", ".scr", ".mui", ".cat", ".man", ".hlp",
    ".inf", ".ini",  # 大部分ini重要
    ".msc", ".gpd", ".ppd",
    ".ttf", ".fon", ".otf",  # 字体文件
}

# 安全删除的目录名（子路径匹配）
SAFE_DIR_PATTERNS = [
    "*/tmp/*", "*/temp/*", "*/Temp/*", "*/TEMP/*",
    "*/__pycache__/*",
    "*/node_modules/*",
    "*/cache/*", "*/Cache/*", "*/CACHE/*",
    "*/log/*", "*/Log/*", "*/logs/*", "*/Logs/*",
    "*/Trash/*",
    "*/.npm/*", "*/.yarn/*", "*/.cargo/*",
    "*/Crash Reports/*",
    "*/Crashpad/*",
    "*/Session Storage/*",
    "*/Local Storage/*",
    "*/Code Cache/*",
    "*/GPUCache/*",
    "*/Service Worker/*",
    "*/Application Cache/*",
    # 浏览器缓存子目录
    "*/Default/Cache/*",
    "*/Default/Code Cache/*",
    "*/Default/GPUCache/*",
    "*/Default/Service Worker/*",
    "*/Default/Session Storage/*",
    "*/Default/Local Storage/*",
    # VS Code 扩展缓存
    "*/.vscode/extensions/*",
    # 微信缓存
    "*/WeChat Files/*/File/*",
    "*/WeChat Files/*/Image/*",
    "*/WeChat Files/*/Video/*",
    "*/WeChat Files/*/Cache/*",
    # QQ 缓存
    "*/QQ Files/*/Cache/*",
    "*/Tencent Files/*/Image/*",
    "*/Tencent Files/*/FileRecv/*",
    # 下载目录
    "*/Downloads/*",
    # 回收站
    "*RECYCLER*",
    "*$Recycle.Bin*",
]


class DiskFileInfo:
    """文件/目录信息"""
    def __init__(self, path, is_dir=False, size=0, modified_time=None):
        self.path = path
        self.name = os.path.basename(path) or path
        self.is_dir = is_dir
        self.size = size
        self.size_display = self._format_size(size)
        self.modified_time = modified_time
        self.category = "unknown"  # safe, caution, system
        self.category_reason = ""
        self.checked = False  # 用户选中
        self.children = []  # 子目录/文件
        self.parent = None

    def _format_size(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / 1024 / 1024:.1f} MB"
        else:
            return f"{size_bytes / 1024 / 1024 / 1024:.2f} GB"


class SafetyClassifier:
    """文件安全分类器"""

    # 已知的浏览器缓存路径模式
    BROWSER_CACHE_PATTERNS = [
        "chrome", "chromium", "edge", "msedge", "firefox", "mozilla",
        "opera", "brave", "vivaldi", "safari", "360chrome", "qqbrowser",
        "liebao", "sogou",
    ]

    # 已知的缓存路径关键词
    CACHE_KEYWORDS = [
        "cache", "缓存", "temp", "临时", "tmp",
        "prefetch", "预取", "thumbnail", "缩略图",
        "crash", "崩溃", "dump", "转储", "log", "日志",
        "backup", "备份", "old", "旧", "recycle", "回收站",
    ]

    # 安全删除的完整文件名
    SAFE_FILES = {
        "Thumbs.db", "thumbs.db", "Desktop.ini", "desktop.ini",
        ".DS_Store", "~$*", "*.tmp", "*.temp",
        "NTUSER.DAT.LOG*", "ntuser.dat.log*",
        "iconcache.db", "IconCache.db",
    }

    @classmethod
    def classify(cls, path, is_dir, size=0):
        """
        对文件/目录进行安全分类
        返回: (category, reason)
        category: 'safe' | 'caution' | 'system' | 'unknown'
        """
        name = os.path.basename(path) or path
        ext = os.path.splitext(name)[1].lower() if not is_dir else ""
        path_lower = path.lower()
        path_parts = Path(path).parts

        # 0. 优先检查：Windows 中可安全清理的子目录
        # 通过路径字符串匹配，不依赖目录层级关系
        path_lower_norm = path_lower.replace("/", "\\")
        if "\\windows\\temp" in path_lower_norm or "\\winnt\\temp" in path_lower_norm:
            return ("safe", "Windows 临时目录，可安全清理")
        if "\\windows\\prefetch" in path_lower_norm:
            return ("safe", "Windows 预取文件，可安全清理")
        if "\\windows\\logs" in path_lower_norm or "\\windows\\log" in path_lower_norm:
            return ("safe", "Windows 日志目录，可安全清理")
        if "\\windows\\debug" in path_lower_norm:
            return ("safe", "Windows 调试日志，可安全清理")
        if "\\windows\\minidump" in path_lower_norm:
            return ("safe", "Windows 崩溃转储，可安全清理")
        if "\\windows\\softwaredistribution\\download" in path_lower_norm:
            return ("safe", "Windows 更新缓存文件，可安全清理")
        if "\\windows\\softwaredistribution" in path_lower_norm:
            return ("caution", "Windows 更新目录，请确认后删除")
        if "\\windows\\installer" in path_lower_norm:
            return ("caution", "MSI 安装缓存，可清理但谨慎操作")

        # 1. 检查是否在系统保护目录中
        for part in path_parts:
            if part in SYSTEM_PROTECTED_DIRS:
                # 检查是否在 system32 等重要目录下
                if part in ("System32", "System", "SysWOW64",
                            "Program Files", "Program Files (x86)"):
                    return ("system", "系统目录，不可删除")
                # Windows 根目录本身不可删除
                if part == "Windows" and len(path_parts) <= 2:
                    return ("system", "Windows 系统目录，不可删除")
                # 某些目录本身不能删，但子目录可清理
                if part in ("AppData", "ProgramData"):
                    # 继续判断子目录
                    pass

        # 检查完整路径是否匹配系统保护
        if is_dir and name in SYSTEM_PROTECTED_DIRS:
            # 检查父目录
            parent = os.path.dirname(path)
            if parent and os.path.basename(parent) in ("C:", "C:\\", "C:/", "D:", "D:\\", "D:/", ""):
                return ("system", f"系统保护目录: {name}")

        # 2. 检查是否是回收站
        if "$Recycle.Bin" in path_parts or "RECYCLER" in path_parts or "回收站" in path_parts:
            return ("safe", "回收站文件，可安全删除")

        # 3. 检查是否是浏览器缓存
        if cls._is_browser_cache(path, is_dir):
            return ("safe", "浏览器缓存，可安全清理")

        # 4. 检查是否是常见的缓存/临时文件
        if cls._is_cache_or_temp(path, is_dir):
            return ("safe", "缓存/临时文件，可安全删除")

        # 5. 检查文件名
        if not is_dir:
            _name = name.lower()
            # 安全文件扩展名
            if ext in SAFE_EXTENSIONS:
                return ("safe", f"安全文件类型: {ext}")

            # 临时文件模式
            if name.startswith("~$") or name.startswith("~"):
                return ("safe", "临时文件，可安全删除")

            # 日志文件
            if ".log" in _name or ".LOG" in name:
                return ("safe", "日志文件，可安全删除")

            # 备份文件
            if ".bak" in _name or ".old" in _name or ".backup" in _name:
                return ("safe", "备份文件，可安全删除")

            # 系统文件扩展名 - 仅在系统目录中才标记为系统文件
            if ext in SYSTEM_EXTENSIONS:
                # 检查是否在系统目录中
                is_in_system_dir = any(
                    p in ("Windows", "System32", "System", "SysWOW64",
                          "Program Files", "Program Files (x86)",
                          "WinSxS", "assembly", "Microsoft.NET")
                    for p in path_parts
                )
                if is_in_system_dir:
                    return ("system", f"系统文件类型: {ext}")
                else:
                    # 用户目录下的 exe/dll 是未知类型
                    return ("unknown", f"可执行文件，请确认是否可删")

        # 6. 检查目录名
        if is_dir:
            _name = name.lower()
            if _name in ("__pycache__",):
                return ("safe", "Python 字节码缓存，可安全删除")

            if _name in ("node_modules", "bower_components"):
                return ("safe", "Node.js 依赖包，可重新安装")

            if _name in (".npm", ".yarn", ".pnpm", ".cargo"):
                return ("safe", "包管理器缓存，可安全清理")

            if _name in ("temp", "tmp", "_tmp", "cache", "_cache", "cached"):
                return ("safe", "缓存/临时目录，可安全清理")

            if _name in ("logs", "log", "_logs"):
                return ("safe", "日志目录，可安全清理")

            if _name in (".git", ".svn"):
                return ("caution", "版本控制目录，如不需要可删除")

            # 检查是否是空目录且无系统文件
            if size == 0:
                return ("safe", "空目录，可安全删除")

        # 7. 检查大小 - 0 字节文件通常是残留
        if not is_dir and size == 0:
            return ("safe", "空文件，可安全删除")

        # 8. 默认 - 未知，需要谨慎
        return ("unknown", "未知类型，请谨慎操作")

    @classmethod
    def _is_browser_cache(cls, path, is_dir):
        """判断是否为浏览器缓存"""
        path_lower = path.lower()
        name = os.path.basename(path).lower()
        path_parts = Path(path).parts
        path_lower_norm = path_lower.replace("/", "\\")

        # 检查 Windows INetCache / Temporary Internet Files
        if "inetcache" in path_lower_norm or "temporary internet files" in path_lower_norm:
            return True

        # 检查浏览器缓存特征路径
        browser_cache_dirs = [
            "cache", "cached", "cache2", "cache3", "cache4",
            "code cache", "gpucache",
            "service worker", "serviceworker",
            "session storage", "local storage",
            "application cache", "appcache",
            "indexeddb", "blob_storage",
            "file system", "filesystem",
            "media cache", "video cache",
            "offline cache",
            "extensions", "extension cache",
            "component cache",
            "crashpad", "crash reports", "crashdumps",
            "dictionaries",
            "safe browsing", "safebrowsing",
            "webfonts", "fontconfig",
            "thumbnails", "thumbnail",
            "favicons", "top sites",
            "network action predictor",
            "visited links",
            "downloads", "download metadata",
        ]

        # 检查是否是浏览器配置文件下的缓存目录
        parent_dir = os.path.basename(os.path.dirname(path)).lower() if not is_dir else ""

        # 检查路径中是否包含浏览器名
        has_browser = any(b in path_lower for b in cls.BROWSER_CACHE_PATTERNS)

        # 缓存关键词
        cache_keywords = [
            "cache", "storage", "indexeddb", "blob_storage",
            "service worker", "code cache", "gpucache",
            "session storage", "local storage",
            "application cache", "appcache",
            "crashpad", "crashdumps", "crash reports",
            "thumbnails", "thumbnail",
            "prefetch",
            "webfonts", "fontconfig",
        ]

        # 检查路径中是否包含缓存关键词
        has_cache = any(c in path_lower for c in cache_keywords)

        if has_browser and has_cache:
            return True

        # 直接检查目录名
        if is_dir and name.lower() in browser_cache_dirs:
            return True

        # 检查文件是否是浏览器缓存文件
        if not is_dir:
            # 浏览器缓存文件通常没有扩展名或者是特定扩展名
            cache_exts = {".fcz", ".fth", ".cache", ".blob", ".ldb", ".log", ".sqlite", ".wal", ".shm"}
            if path_lower.endswith(tuple(cache_exts)):
                if has_browser or has_cache:
                    return True
            # Chrome 缓存文件通常是 6 位十六进制命名
            if len(name) == 6 and all(c in "0123456789abcdef" for c in name.lower()):
                if "cache" in path_lower:
                    return True

        # 通用缓存检测：路径中包含 cache 关键词，且不在明显非缓存目录下
        if has_cache:
            # 排除系统目录
            if not any(p in path_lower_norm for p in [
                "\\system32\\", "\\syswow64\\", "\\program files\\",
                "\\windows\\system", "\\windows\\fonts",
            ]):
                return True

        return False

    @classmethod
    def _is_cache_or_temp(cls, path, is_dir):
        """判断是否为缓存/临时文件"""
        path_lower = path.lower()
        name = os.path.basename(path).lower()
        path_parts = Path(path).parts

        # Windows 临时目录
        if "\\temp\\" in path or "\\tmp\\" in path:
            return True
        if "/temp/" in path or "/tmp/" in path:
            return True

        # 环境变量中的临时目录
        if "local\\temp" in path_lower or "locallow\\temp" in path_lower:
            return True

        # 常见的 IDE 缓存
        ide_cache_dirs = {
            ".vscode", ".idea", ".eclipse", ".settings",
            ".metadata", ".recommenders",
            "vscode", "intellij", "pycharm",
        }

        if is_dir and name.lower() in ide_cache_dirs:
            return True

        # 日志文件特殊处理
        if not is_dir and name.endswith((".log", ".LOG")):
            return True

        # 日志轮转文件
        if not is_dir and any(name.endswith(f".log.{i}") for i in range(1, 10)):
            return True

        return False


class SmartDiskCleaner:
    """主应用程序"""

    def __init__(self, root):
        self.root = root
        self.root.title("智能磁盘清理工具 - SmartDiskCleaner")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)

        # 设置图标（如果有的话）
        try:
            if platform.system() == "Windows":
                self.root.iconbitmap(default="")
        except:
            pass

        # 状态变量
        self.scan_path = StringVar(value="C:\\")
        self.scanning = False
        self.current_scan_path = ""
        self.file_list = []  # 所有扫描到的文件信息
        self.tree_items = {}  # path -> tree item id
        self.total_size = 0
        self.safe_size = 0
        self.caution_size = 0
        self.system_size = 0
        self.unknown_size = 0

        # 过滤选项
        self.show_safe = BooleanVar(value=True)
        self.show_caution = BooleanVar(value=True)
        self.show_system = BooleanVar(value=False)
        self.show_unknown = BooleanVar(value=True)
        self.show_files = BooleanVar(value=True)
        self.show_dirs = BooleanVar(value=True)

        # 排序选项
        self.sort_by = StringVar(value="size")
        self.sort_reverse = BooleanVar(value=True)

        # 深色/浅色模式
        self.dark_mode = BooleanVar(value=False)

        # 构建 UI
        self._build_ui()

        # 绑定事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # 初始状态
        self._update_stats()

    def _build_ui(self):
        """构建用户界面"""
        # 主菜单
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="选择扫描路径...", command=self._select_path, accelerator="Ctrl+O")
        file_menu.add_command(label="刷新", command=self._start_scan, accelerator="F5")
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_close, accelerator="Alt+F4")

        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="工具", menu=tools_menu)
        tools_menu.add_command(label="清理已选安全文件", command=self._clean_selected)
        tools_menu.add_command(label="清理所有安全文件", command=self._clean_all_safe)
        tools_menu.add_separator()
        tools_menu.add_command(label="分类统计...", command=self._show_stats)

        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="使用说明", command=self._show_help)
        help_menu.add_command(label="关于", command=self._show_about)

        # 主框架
        main_frame = ttk.Frame(self.root, padding=5)
        main_frame.pack(fill="both", expand=True)

        # ====== 顶部工具栏 ======
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill="x", pady=(0, 5))

        ttk.Label(toolbar, text="扫描路径:").pack(side="left", padx=(0, 5))

        self.path_entry = ttk.Entry(toolbar, textvariable=self.scan_path, width=60)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.btn_browse = ttk.Button(toolbar, text="浏览...", command=self._select_path, width=8)
        self.btn_browse.pack(side="left", padx=(0, 5))

        self.btn_scan = ttk.Button(toolbar, text="开始扫描", command=self._start_scan, width=10)
        self.btn_scan.pack(side="left", padx=(0, 5))

        # ====== 进度条（单独一行，不受文字影响） ======
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=(0, 2))

        self.progress = Progressbar(progress_frame, mode="determinate")
        self.progress.pack(fill="x", expand=True)

        # ====== 状态文字（单独一行，不挤压进度条） ======
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(0, 5))

        self.lbl_status = ttk.Label(status_frame, text="就绪", font=("", 9))
        self.lbl_status.pack(side="left")

        self.lbl_scan_info = ttk.Label(status_frame, text="", foreground="#666666")
        self.lbl_scan_info.pack(side="right", padx=(10, 0))

        # ====== 统计信息栏 ======
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill="x", pady=(0, 5))

        self.lbl_total = ttk.Label(stats_frame, text="总大小: 0 B", font=("", 10, "bold"))
        self.lbl_total.pack(side="left", padx=(0, 15))

        self.lbl_safe = ttk.Label(stats_frame, text="🟢 可安全删除: 0 B",
                                  foreground="#2e7d32", font=("", 10))
        self.lbl_safe.pack(side="left", padx=(0, 15))

        self.lbl_caution = ttk.Label(stats_frame, text="🟡 谨慎删除: 0 B",
                                     foreground="#e65100", font=("", 10))
        self.lbl_caution.pack(side="left", padx=(0, 15))

        self.lbl_system = ttk.Label(stats_frame, text="🔴 系统文件: 0 B",
                                    foreground="#c62828", font=("", 10))
        self.lbl_system.pack(side="left", padx=(0, 15))

        self.lbl_unknown = ttk.Label(stats_frame, text="⚪ 未知: 0 B",
                                     foreground="#546e7a", font=("", 10))
        self.lbl_unknown.pack(side="left")

        # ====== 主内容区（左右分栏） ======
        content_pane = ttk.PanedWindow(main_frame, orient="horizontal")
        content_pane.pack(fill="both", expand=True)

        # ====== 左侧：过滤面板 ======
        left_frame = ttk.LabelFrame(content_pane, text="筛选", width=160)
        content_pane.add(left_frame, weight=0)

        filter_frame = ttk.Frame(left_frame, padding=8)
        filter_frame.pack(fill="both", expand=True)

        ttk.Label(filter_frame, text="分类过滤:", font=("", 9, "bold")).pack(anchor="w", pady=(0, 5))

        self.cb_show_safe = ttk.Checkbutton(filter_frame, text="🟢 安全可删",
                                            variable=self.show_safe,
                                            command=self._apply_filter)
        self.cb_show_safe.pack(anchor="w", pady=2)

        self.cb_show_caution = ttk.Checkbutton(filter_frame, text="🟡 谨慎操作",
                                               variable=self.show_caution,
                                               command=self._apply_filter)
        self.cb_show_caution.pack(anchor="w", pady=2)

        self.cb_show_system = ttk.Checkbutton(filter_frame, text="🔴 系统文件",
                                              variable=self.show_system,
                                              command=self._apply_filter)
        self.cb_show_system.pack(anchor="w", pady=2)

        self.cb_show_unknown = ttk.Checkbutton(filter_frame, text="⚪ 未知类型",
                                               variable=self.show_unknown,
                                               command=self._apply_filter)
        self.cb_show_unknown.pack(anchor="w", pady=2)

        ttk.Separator(filter_frame, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(filter_frame, text="类型过滤:", font=("", 9, "bold")).pack(anchor="w", pady=(0, 5))

        self.cb_show_files = ttk.Checkbutton(filter_frame, text="文件",
                                             variable=self.show_files,
                                             command=self._apply_filter)
        self.cb_show_files.pack(anchor="w", pady=2)

        self.cb_show_dirs = ttk.Checkbutton(filter_frame, text="目录",
                                            variable=self.show_dirs,
                                            command=self._apply_filter)
        self.cb_show_dirs.pack(anchor="w", pady=2)

        ttk.Separator(filter_frame, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(filter_frame, text="排序方式:", font=("", 9, "bold")).pack(anchor="w", pady=(0, 5))

        sort_frame = ttk.Frame(filter_frame)
        sort_frame.pack(fill="x", pady=2)

        ttk.Radiobutton(sort_frame, text="大小", variable=self.sort_by,
                        value="size", command=self._apply_sort).pack(anchor="w")
        ttk.Radiobutton(sort_frame, text="名称", variable=self.sort_by,
                        value="name", command=self._apply_sort).pack(anchor="w")
        ttk.Radiobutton(sort_frame, text="路径", variable=self.sort_by,
                        value="path", command=self._apply_sort).pack(anchor="w")
        ttk.Radiobutton(sort_frame, text="分类", variable=self.sort_by,
                        value="category", command=self._apply_sort).pack(anchor="w")

        ttk.Checkbutton(sort_frame, text="降序", variable=self.sort_reverse,
                        command=self._apply_sort).pack(anchor="w", pady=(5, 0))

        ttk.Separator(filter_frame, orient="horizontal").pack(fill="x", pady=10)

        # 清理按钮
        ttk.Label(filter_frame, text="清理操作:", font=("", 9, "bold")).pack(anchor="w", pady=(0, 5))

        self.btn_clean_selected = ttk.Button(
            filter_frame, text="删除选中的安全文件",
            command=self._clean_selected, style="success.TButton"
        )
        self.btn_clean_selected.pack(fill="x", pady=2)

        self.btn_clean_all = ttk.Button(
            filter_frame, text="删除所有安全文件",
            command=self._clean_all_safe, style="success.TButton"
        )
        self.btn_clean_all.pack(fill="x", pady=2)

        ttk.Button(filter_frame, text="全选安全文件",
                   command=self._select_all_safe).pack(fill="x", pady=2)
        ttk.Button(filter_frame, text="全不选",
                   command=self._deselect_all).pack(fill="x", pady=2)

        # ====== 右侧：文件列表 ======
        right_frame = ttk.Frame(content_pane)
        content_pane.add(right_frame, weight=1)

        # 树状视图
        columns = ("name", "size", "category", "reason", "modified", "path")
        self.tree = ttk.Treeview(right_frame, columns=columns,
                                 show="tree headings", selectmode="extended")

        # 列定义
        self.tree.heading("#0", text="", anchor="w")
        self.tree.column("#0", width=0, stretch=False)

        self.tree.heading("name", text="名称", anchor="w",
                          command=lambda: self._sort_by_click("name"))
        self.tree.column("name", width=250, minwidth=150, anchor="w")

        self.tree.heading("size", text="大小", anchor="e",
                          command=lambda: self._sort_by_click("size"))
        self.tree.column("size", width=100, minwidth=80, anchor="e")

        self.tree.heading("category", text="分类", anchor="w",
                          command=lambda: self._sort_by_click("category"))
        self.tree.column("category", width=100, minwidth=80, anchor="w")

        self.tree.heading("reason", text="说明", anchor="w")
        self.tree.column("reason", width=200, minwidth=100, anchor="w")

        self.tree.heading("modified", text="修改时间", anchor="w",
                          command=lambda: self._sort_by_click("modified"))
        self.tree.column("modified", width=150, minwidth=100, anchor="w")

        self.tree.heading("path", text="完整路径", anchor="w",
                          command=lambda: self._sort_by_click("path"))
        self.tree.column("path", width=300, minwidth=100, anchor="w")

        # 滚动条
        vsb = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(right_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        # 标签颜色映射
        self.tree.tag_configure("safe", background="#e8f5e9", foreground="#1b5e20")
        self.tree.tag_configure("caution", background="#fff3e0", foreground="#e65100")
        self.tree.tag_configure("system", background="#ffebee", foreground="#c62828")
        self.tree.tag_configure("unknown", background="#f5f5f5", foreground="#546e7a")
        self.tree.tag_configure("dir", font=("", 9, "bold"))

        # 绑定事件
        self.tree.bind("<Double-1>", self._on_item_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<space>", self._toggle_check)

        # 键盘快捷键
        self.root.bind("<Control-o>", lambda e: self._select_path())
        self.root.bind("<F5>", lambda e: self._start_scan())
        self.root.bind("<Delete>", lambda e: self._clean_selected())

        # 底部状态栏
        status_bar = ttk.Frame(main_frame)
        status_bar.pack(fill="x", pady=(5, 0))

        self.lbl_items_count = ttk.Label(status_bar, text="项目: 0")
        self.lbl_items_count.pack(side="left", padx=(0, 20))

        self.lbl_file_count = ttk.Label(status_bar, text="文件: 0")
        self.lbl_file_count.pack(side="left", padx=(0, 20))

        self.lbl_dir_count = ttk.Label(status_bar, text="目录: 0")
        self.lbl_dir_count.pack(side="left", padx=(0, 20))

        self.lbl_selected_count = ttk.Label(status_bar, text="已选: 0")
        self.lbl_selected_count.pack(side="left", padx=(0, 20))

        # 设置样式
        self._setup_styles()

    def _setup_styles(self):
        """设置样式"""
        style = ttk.Style()
        style.configure("success.TButton", foreground="#2e7d32")
        style.configure("danger.TButton", foreground="#c62828")
        style.configure("info.TButton", foreground="#1565c0")

    def _select_path(self):
        """选择扫描路径"""
        path = filedialog.askdirectory(
            title="选择要扫描的目录",
            initialdir=self.scan_path.get() if os.path.exists(self.scan_path.get()) else "C:\\"
        )
        if path:
            self.scan_path.set(path)
            self._start_scan()

    def _start_scan(self):
        """开始扫描（在新线程中）"""
        if self.scanning:
            messagebox.showwarning("提示", "正在扫描中，请等待完成")
            return

        path = self.scan_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("错误", "路径不存在，请重新选择")
            return

        self.scanning = True
        self.current_scan_path = path
        self.btn_scan.config(text="扫描中...", state="disabled")
        self.btn_browse.config(state="disabled")
        self.lbl_status.config(text="正在估算文件数量...")
        self.progress["mode"] = "indeterminate"
        self.progress.start(15)

        # 清空之前的结果
        self.file_list = []
        self.tree_items = {}
        self.tree.delete(*self.tree.get_children())
        self.total_size = 0
        self.safe_size = 0
        self.caution_size = 0
        self.system_size = 0
        self.unknown_size = 0
        self.total_estimated = 0
        self._update_stats()

        # 先启动计数线程（快速估算总量）
        count_thread = threading.Thread(target=self._count_thread, args=(path,), daemon=True)
        count_thread.start()

    def _count_thread(self, path):
        """第一阶段：快速计数（不 stat 文件，仅遍历目录结构）"""
        try:
            self.root.after(0, lambda: self.lbl_status.config(text="正在估算文件数量（第一阶段）..."))

            total_count = 0
            for current_dir, dirs, files in os.walk(path, topdown=True):
                # 过滤不可访问的目录
                if "System Volume Information" in dirs:
                    dirs.remove("System Volume Information")
                if "$Recycle.Bin" in dirs:
                    dirs.remove("$Recycle.Bin")

                total_count += len(dirs) + len(files)

                # Windows 深层目录跳过计数（太耗时）
                parts = current_dir.split(os.sep)
                if "Windows" in parts and len(parts) > 5:
                    dirs.clear()

                if total_count > 500000:
                    break

            # 计数完成，开始实际扫描
            self.root.after(0, lambda: self._on_count_complete(path, total_count))

        except Exception as e:
            # 如果计数失败，直接开始扫描（没有进度条显示）
            self.root.after(0, lambda: self._start_scan_phase2(path, 0))

    def _on_count_complete(self, path, total_count):
        """计数完成，进入第二阶段：实际扫描"""
        self.total_estimated = max(total_count, 1)  # 防止除以零
        self.progress.stop()
        self.progress["mode"] = "determinate"
        self.progress["value"] = 0
        self.lbl_status.config(text=f"共发现约 {total_count} 个项目，开始扫描...")

        # 启动实际扫描线程
        scan_thread = threading.Thread(target=self._scan_thread, args=(path, total_count), daemon=True)
        scan_thread.start()

    def _scan_thread(self, path, total_estimated):
        """第二阶段：实际扫描，带真实进度条"""
        try:
            all_items = []
            total_found = 0
            dirs_count = 0
            files_count = 0
            start_time = time.time()
            last_update_time = 0

            # 分类根目录
            root_path = path
            cat, reason = SafetyClassifier.classify(root_path, is_dir=True, size=0)
            root_info = DiskFileInfo(root_path, is_dir=True, size=0,
                                     modified_time=datetime.now())
            root_info.category = cat
            root_info.category_reason = reason
            all_items.append(root_info)

            # 遍历目录
            for current_dir, dirs, files in os.walk(path, topdown=True):
                # 过滤掉一些无法访问的目录
                if "System Volume Information" in dirs:
                    dirs.remove("System Volume Information")
                if "$Recycle.Bin" in dirs:
                    dirs.remove("$Recycle.Bin")

                # 快速检查是否在系统目录中
                if "Windows" in current_dir.split(os.sep):
                    parts = current_dir.split(os.sep)
                    if len(parts) > 5:
                        continue

                # 处理目录
                for d in dirs[:]:
                    dir_path = os.path.join(current_dir, d)
                    try:
                        stat = os.stat(dir_path)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        file_info = DiskFileInfo(dir_path, is_dir=True,
                                                 size=0, modified_time=mtime)
                        cat, reason = SafetyClassifier.classify(
                            dir_path, is_dir=True, size=0)
                        file_info.category = cat
                        file_info.category_reason = reason
                        all_items.append(file_info)
                        dirs_count += 1
                        total_found += 1
                    except (OSError, PermissionError):
                        continue

                # 处理文件
                for f in files:
                    file_path = os.path.join(current_dir, f)
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        file_info = DiskFileInfo(file_path, is_dir=False,
                                                 size=size, modified_time=mtime)
                        cat, reason = SafetyClassifier.classify(
                            file_path, is_dir=False, size=size)
                        file_info.category = cat
                        file_info.category_reason = reason
                        all_items.append(file_info)
                        files_count += 1
                        total_found += 1
                    except (OSError, PermissionError):
                        continue

                # 更新进度（每 0.2 秒或每处理 500 个项目更新一次，避免卡 UI）
                now = time.time()
                elapsed = now - start_time
                if now - last_update_time > 0.2 or total_found % 500 == 0:
                    last_update_time = now
                    self.root.after(0, self._update_scan_progress,
                                    current_dir, total_found, total_estimated, elapsed)

                # 限制最大扫描数量（防止内存溢出）
                if len(all_items) > 500000:
                    break

            # 扫描完成，更新 UI
            self.root.after(0, self._on_scan_complete, all_items,
                            time.time() - start_time)

        except Exception as e:
            self.root.after(0, self._on_scan_error, str(e))

    def _update_scan_progress(self, current_dir, count, total, elapsed):
        """更新扫描进度（带真实百分比）"""
        if total > 0:
            percent = min(int(count * 100 / total), 99)
            self.progress["value"] = percent
        else:
            percent = 0

        # 速率计算
        rate = count / elapsed if elapsed > 0 else 0

        # 预估剩余时间
        remaining = (total - count) / rate if rate > 0 else 0
        if remaining > 0:
            if remaining > 60:
                eta_str = f"剩余约 {remaining/60:.0f} 分钟"
            else:
                eta_str = f"剩余约 {remaining:.0f} 秒"
        else:
            eta_str = "即将完成"

        self.lbl_status.config(text=f"正在扫描: {os.path.basename(current_dir)}")
        self.lbl_scan_info.config(
            text=f"进度 {percent}%  |  已处理 {count}/{total} 个项目  |  {eta_str}  |  用时 {elapsed:.0f}s"
        )

    def _on_scan_complete(self, all_items, elapsed):
        """扫描完成后的处理"""
        self.progress.stop()
        self.progress["mode"] = "determinate"
        self.progress["value"] = 100

        self.file_list = all_items
        self.btn_scan.config(text="重新扫描", state="normal")
        self.btn_browse.config(state="normal")

        # 计算统计
        self._calculate_stats()
        self._update_stats()

        # 填充树视图
        self._populate_tree()

        # 更新状态
        dirs = sum(1 for item in all_items if item.is_dir)
        files = len(all_items) - dirs
        self.lbl_status.config(text=f"扫描完成! 用时 {elapsed:.1f}s")
        self.lbl_scan_info.config(text="")
        self.lbl_items_count.config(text=f"项目: {len(all_items)}")
        self.lbl_file_count.config(text=f"文件: {files}")
        self.lbl_dir_count.config(text=f"目录: {dirs}")

        self.scanning = False

    def _on_scan_error(self, error):
        """扫描出错"""
        self.progress.stop()
        self.progress["mode"] = "determinate"
        self.progress["value"] = 0
        self.btn_scan.config(text="重新扫描", state="normal")
        self.btn_browse.config(state="normal")
        self.lbl_status.config(text="扫描出错")
        self.scanning = False
        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error}")

    def _calculate_stats(self):
        """计算统计信息"""
        self.total_size = sum(item.size for item in self.file_list)
        self.safe_size = sum(item.size for item in self.file_list
                             if item.category == "safe")
        self.caution_size = sum(item.size for item in self.file_list
                                if item.category == "caution")
        self.system_size = sum(item.size for item in self.file_list
                               if item.category == "system")
        self.unknown_size = sum(item.size for item in self.file_list
                                if item.category == "unknown")

    def _update_stats(self):
        """更新统计显示"""
        self.lbl_total.config(text=f"总大小: {self._fmt_size(self.total_size)}")
        self.lbl_safe.config(text=f"🟢 可安全删除: {self._fmt_size(self.safe_size)}")
        self.lbl_caution.config(text=f"🟡 谨慎删除: {self._fmt_size(self.caution_size)}")
        self.lbl_system.config(text=f"🔴 系统文件: {self._fmt_size(self.system_size)}")
        self.lbl_unknown.config(text=f"⚪ 未知: {self._fmt_size(self.unknown_size)}")

    def _fmt_size(self, size_bytes):
        """格式化大小"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / 1024 / 1024:.1f} MB"
        else:
            return f"{size_bytes / 1024 / 1024 / 1024:.2f} GB"

    def _populate_tree(self):
        """填充树视图"""
        self.tree.delete(*self.tree.get_children())
        self.tree_items = {}

        # 排序
        items = self._sort_items(self.file_list)

        # 过滤
        items = self._filter_items(items)

        # 插入
        for item in items:
            self._insert_tree_item(item)

    def _insert_tree_item(self, item):
        """插入一个树项目"""
        # 获取父节点
        parent_path = os.path.dirname(item.path) if item.path != self.current_scan_path else ""
        parent_id = self.tree_items.get(parent_path, "")

        # 分类标签
        cat_map = {
            "safe": "🟢 安全可删",
            "caution": "🟡 谨慎操作",
            "system": "🔴 系统文件",
            "unknown": "⚪ 未知类型",
        }
        cat_display = cat_map.get(item.category, item.category)

        # 修改时间
        mtime_str = item.modified_time.strftime("%Y-%m-%d %H:%M") if item.modified_time else ""

        # 插入
        values = (
            item.name,
            item.size_display,
            cat_display,
            item.category_reason,
            mtime_str,
            item.path,
        )
        tag = item.category
        if item.is_dir:
            tag = f"{tag}_dir"

        try:
            iid = self.tree.insert(parent_id, "end", text="",
                                   values=values, tags=(item.category,))
            self.tree_items[item.path] = iid
        except Exception:
            pass

    def _sort_items(self, items):
        """排序"""
        sort_key = self.sort_by.get()
        reverse = self.sort_reverse.get()

        if sort_key == "name":
            items.sort(key=lambda x: x.name.lower(), reverse=reverse)
        elif sort_key == "size":
            items.sort(key=lambda x: x.size, reverse=reverse)
        elif sort_key == "path":
            items.sort(key=lambda x: x.path.lower(), reverse=reverse)
        elif sort_key == "category":
            cat_order = {"safe": 0, "caution": 1, "unknown": 2, "system": 3}
            items.sort(key=lambda x: (cat_order.get(x.category, 99), x.name.lower()),
                       reverse=reverse)
        elif sort_key == "modified":
            items.sort(key=lambda x: x.modified_time or datetime.min,
                       reverse=reverse)

        return items

    def _filter_items(self, items):
        """过滤"""
        filtered = []
        for item in items:
            # 分类过滤
            if item.category == "safe" and not self.show_safe.get():
                continue
            if item.category == "caution" and not self.show_caution.get():
                continue
            if item.category == "system" and not self.show_system.get():
                continue
            if item.category == "unknown" and not self.show_unknown.get():
                continue

            # 类型过滤
            if item.is_dir and not self.show_dirs.get():
                continue
            if not item.is_dir and not self.show_files.get():
                continue

            filtered.append(item)

        return filtered

    def _apply_filter(self):
        """应用过滤"""
        self._populate_tree()

    def _apply_sort(self):
        """应用排序"""
        self._populate_tree()

    def _sort_by_click(self, col):
        """点击列头排序"""
        if self.sort_by.get() == col:
            self.sort_reverse.set(not self.sort_reverse.get())
        else:
            self.sort_by.set(col)
            self.sort_reverse.set(True)
        self._apply_sort()

    def _on_item_double_click(self, event):
        """双击项目"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            path = item["values"][5] if len(item["values"]) > 5 else ""
            if path and os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        self.scan_path.set(path)
                        self._start_scan()
                    else:
                        # 打开文件所在目录
                        if platform.system() == "Windows":
                            os.startfile(os.path.dirname(path))
                        else:
                            import subprocess
                            subprocess.run(["open", os.path.dirname(path)])
                except Exception as e:
                    messagebox.showerror("错误", f"无法打开: {e}")

    def _on_right_click(self, event):
        """右键菜单"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        path = item["values"][5] if len(item["values"]) > 5 else ""

        menu = Menu(self.root, tearoff=0)
        menu.add_command(label="查看文件位置", command=lambda: self._open_file_location(path))
        menu.add_command(label="复制路径", command=lambda: self._copy_path(path))
        menu.add_separator()
        menu.add_command(label="删除此文件（安全删除）",
                         command=lambda: self._delete_single_item(path))
        menu.add_separator()
        menu.add_command(label="刷新此目录", command=lambda: self._refresh_path(path))

        menu.post(event.x_root, event.y_root)

    def _open_file_location(self, path):
        """打开文件位置"""
        if path and os.path.exists(path):
            try:
                if platform.system() == "Windows":
                    os.startfile(os.path.dirname(path) if os.path.isfile(path) else path)
                else:
                    import subprocess
                    subprocess.run(["open", os.path.dirname(path) if os.path.isfile(path) else path])
            except Exception as e:
                messagebox.showerror("错误", f"无法打开: {e}")

    def _copy_path(self, path):
        """复制路径到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.lbl_status.config(text=f"已复制路径: {path}")

    def _toggle_check(self, event):
        """空格切换选中"""
        # 简单实现：选中/取消选中
        pass

    def _select_all_safe(self):
        """选中所有安全文件"""
        for item in self.file_list:
            if item.category == "safe":
                item.checked = True
        self._update_selected_count()
        self.lbl_status.config(text="已选中所有安全文件")

    def _deselect_all(self):
        """取消所有选中"""
        for item in self.file_list:
            item.checked = False
        self._update_selected_count()
        self.lbl_status.config(text="已取消所有选中")

    def _update_selected_count(self):
        """更新选中计数"""
        count = sum(1 for item in self.file_list if item.checked)
        size = sum(item.size for item in self.file_list if item.checked)
        self.lbl_selected_count.config(text=f"已选: {count} ({self._fmt_size(size)})")

    def _clean_selected(self):
        """删除选中的安全文件"""
        selected = [item for item in self.file_list if item.checked]
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的文件\n（点击左侧「全选安全文件」可快速选中）")
            return

        # 过滤出安全或谨慎的文件
        safe_items = [item for item in selected if item.category == "safe"]
        caution_items = [item for item in selected if item.category == "caution"]

        if not safe_items and not caution_items:
            messagebox.showinfo("提示", "选中的文件没有可安全删除的项")
            return

        msg = f"确定要删除以下文件吗？\n\n"
        if safe_items:
            safe_size = sum(item.size for item in safe_items)
            msg += f"🟢 安全文件: {len(safe_items)} 个 ({self._fmt_size(safe_size)})\n"
        if caution_items:
            caution_size = sum(item.size for item in caution_items)
            msg += f"🟡 谨慎文件: {len(caution_items)} 个 ({self._fmt_size(caution_size)})\n\n"
        msg += "此操作不可撤销！"

        if not messagebox.askyesno("确认删除", msg, icon="warning"):
            return

        # 执行删除
        self._perform_deletion(selected)

    def _clean_all_safe(self):
        """删除所有安全文件"""
        safe_items = [item for item in self.file_list if item.category == "safe"]
        if not safe_items:
            messagebox.showinfo("提示", "没有找到可安全删除的文件")
            return

        safe_size = sum(item.size for item in safe_items)
        msg = (f"确定要删除所有可安全删除的文件吗？\n\n"
               f"🟢 共 {len(safe_items)} 个文件\n"
               f"📦 释放空间: {self._fmt_size(safe_size)}\n\n"
               f"这些文件包括：\n"
               f"- 临时文件\n"
               f"- 缓存文件\n"
               f"- 日志文件\n"
               f"- 回收站文件\n"
               f"- 浏览器缓存\n"
               f"- 崩溃转储\n"
               f"- 空文件/目录\n\n"
               f"此操作不可撤销！")

        if not messagebox.askyesno("确认删除所有安全文件", msg, icon="warning"):
            return

        # 执行删除
        self._perform_deletion(safe_items)

    def _delete_single_item(self, path):
        """删除单个项目"""
        if not path or not os.path.exists(path):
            return

        name = os.path.basename(path)
        if not messagebox.askyesno("确认删除", f"确定要删除「{name}」吗？\n此操作不可撤销！",
                                   icon="warning"):
            return

        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
            self.lbl_status.config(text=f"已删除: {name}")
            self._start_scan()  # 刷新
        except Exception as e:
            messagebox.showerror("删除失败", f"无法删除 {name}:\n{e}")

    def _perform_deletion(self, items):
        """执行删除操作"""
        deleted_count = 0
        deleted_size = 0
        errors = []

        # 先排序：先删文件，再删目录（避免父目录已删导致子文件出错）
        files_to_delete = [item for item in items if not item.is_dir]
        dirs_to_delete = [item for item in items if item.is_dir]

        # 按路径长度降序排列目录（先删子目录）
        dirs_to_delete.sort(key=lambda x: x.path, reverse=True)

        # 删除文件
        for item in files_to_delete:
            try:
                if os.path.exists(item.path) and os.path.isfile(item.path):
                    os.remove(item.path)
                    deleted_count += 1
                    deleted_size += item.size
            except Exception as e:
                errors.append(f"{item.name}: {e}")

        # 删除目录
        for item in dirs_to_delete:
            try:
                if os.path.exists(item.path) and os.path.isdir(item.path):
                    shutil.rmtree(item.path, ignore_errors=True)
                    deleted_count += 1
                    deleted_size += item.size
            except Exception as e:
                errors.append(f"{item.name}: {e}")

        # 显示结果
        result_msg = (f"删除完成！\n\n"
                      f"✅ 成功删除: {deleted_count} 个项目\n"
                      f"📦 释放空间: {self._fmt_size(deleted_size)}")

        if errors:
            result_msg += f"\n\n❌ 失败: {len(errors)} 个\n"
            for err in errors[:10]:  # 最多显示10个错误
                result_msg += f"\n  - {err}"

        messagebox.showinfo("清理结果", result_msg)

        # 刷新扫描
        self._start_scan()

    def _refresh_path(self, path):
        """刷新某个路径"""
        if path and os.path.exists(path):
            self.scan_path.set(path if os.path.isdir(path) else os.path.dirname(path))
            self._start_scan()

    def _show_stats(self):
        """显示详细统计"""
        if not self.file_list:
            messagebox.showinfo("统计", "请先扫描目录")
            return

        # 按分类统计
        cat_counts = {}
        cat_sizes = {}
        for item in self.file_list:
            c = item.category
            cat_counts[c] = cat_counts.get(c, 0) + 1
            cat_sizes[c] = cat_sizes.get(c, 0) + item.size

        # 按文件类型统计（仅安全文件）
        type_stats = {}
        for item in self.file_list:
            if item.category == "safe" and not item.is_dir:
                ext = os.path.splitext(item.name)[1].lower() or "(无扩展名)"
                if ext not in type_stats:
                    type_stats[ext] = {"count": 0, "size": 0}
                type_stats[ext]["count"] += 1
                type_stats[ext]["size"] += item.size

        # 构建统计信息
        lines = ["📊 磁盘清理统计", "=" * 40, ""]
        lines.append(f"扫描路径: {self.current_scan_path}")
        lines.append(f"总项目数: {len(self.file_list)}")
        lines.append("")

        cat_names = {
            "safe": "🟢 可安全删除",
            "caution": "🟡 谨慎删除",
            "system": "🔴 系统文件",
            "unknown": "⚪ 未知类型",
        }
        for cat in ["safe", "caution", "unknown", "system"]:
            count = cat_counts.get(cat, 0)
            size = cat_sizes.get(cat, 0)
            if count > 0:
                lines.append(f"{cat_names.get(cat, cat)}: {count} 项, {self._fmt_size(size)}")

        lines.append("")
        lines.append("📁 安全文件类型分布:")
        lines.append("-" * 30)

        # 排序
        sorted_types = sorted(type_stats.items(), key=lambda x: x[1]["size"], reverse=True)
        for ext, info in sorted_types[:20]:
            lines.append(f"  {ext:15s}  {info['count']:5d} 个  {self._fmt_size(info['size'])}")

        if len(sorted_types) > 20:
            lines.append(f"  ... 还有 {len(sorted_types) - 20} 种类型")

        text = "\n".join(lines)

        # 显示在对话框
        dialog = Toplevel(self.root)
        dialog.title("详细统计")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        text_widget = Text(dialog, wrap=WORD, padx=10, pady=10)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", text)
        text_widget.config(state=DISABLED)

        scrollbar = ttk.Scrollbar(text_widget, command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.config(yscrollcommand=scrollbar.set)

        ttk.Button(dialog, text="关闭", command=dialog.destroy).pack(pady=10)

    def _show_help(self):
        """显示帮助信息"""
        help_text = """📖 智能磁盘清理工具 使用说明

🔍 基本用法
1. 选择要扫描的磁盘或目录（点击「浏览...」或直接输入路径）
2. 点击「开始扫描」等待扫描完成
3. 查看结果，文件会按颜色分类：
   🟢 绿色 = 可安全删除（缓存、临时文件、日志等）
   🟡 橙色 = 谨慎操作（建议确认后再删）
   🔴 红色 = 系统文件（不要删除）
   ⚪ 灰色 = 未知类型（请自行判断）

🧹 清理文件
- 点击左侧「全选安全文件」→「删除选中的安全文件」
- 或直接点击「删除所有安全文件」
- 也可以右键单个文件选择删除

🎯 筛选功能
左侧面板可以按分类、类型筛选，按大小/名称/分类排序

⚠️ 注意事项
- 删除前请确认文件内容
- 建议先清理安全文件（绿色）
- 谨慎对待橙色标记的文件
- 红色系统文件请勿删除
- 清理后建议重启电脑

💡 建议清理的目录
- C:\\Windows\\Temp
- C:\\Users\\你的用户名\\AppData\\Local\\Temp
- 浏览器缓存目录
- 回收站
- 各种软件的 Cache 目录
        """
        messagebox.showinfo("使用说明", help_text)

    def _show_about(self):
        """显示关于信息"""
        about_text = """智能磁盘清理工具 SmartDiskCleaner v1.0

🖥️ 功能特点：
- 快速扫描磁盘空间使用情况
- 智能分类文件安全等级
- 一键清理安全文件
- 可视化统计信息

🛡️ 安全设计：
- 系统文件自动保护
- 分类分级清理建议
- 删除前确认提示

📝 提示：本工具会智能识别可安全删除的文件，
但请在使用前自行确认，我们对删除造成的任何
损失不承担责任。

💡 建议定期清理以下内容：
- 系统临时文件
- 浏览器缓存
- 回收站
- 应用程序缓存
        """
        messagebox.showinfo("关于", about_text)

    def _on_close(self):
        """关闭窗口"""
        if self.scanning:
            if not messagebox.askyesno("确认", "扫描正在进行中，确定要退出吗？"):
                return
        self.root.destroy()


def main():
    """主函数"""
    root = Tk()
    app = SmartDiskCleaner(root)
    root.mainloop()


if __name__ == "__main__":
    main()