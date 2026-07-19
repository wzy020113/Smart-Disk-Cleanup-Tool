#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C 盘空间分析与安全清理工具。

空间分析会遍历 C 盘并建立目录大小树；清理功能只接受明确的 Temp、
浏览器 Cache 和 Windows 缩略图缓存文件，未知文件不会自动删除。
"""

import os
import threading
import time
from datetime import datetime
from tkinter import Tk, StringVar, ttk, messagebox


SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:").rstrip("\\/")
SCAN_ROOT = SYSTEM_DRIVE + "\\"

BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".com", ".scr",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".pyc", ".pyd",
    ".lnk", ".url", ".msi", ".msp",
}

TEMP_EXTENSIONS = {
    ".tmp", ".temp", ".log", ".dmp", ".mdmp", ".etl", ".cache",
    ".bak", ".old",
}


class DirNode:
    def __init__(self, path, name):
        self.path = path
        self.name = name
        self.size = 0
        self.files = 0
        self.children = []


class Candidate:
    def __init__(self, path, root, reason, size, mtime):
        self.path = path
        self.root = root
        self.reason = reason
        self.size = size
        self.mtime = mtime


def fast_key(path):
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def canonical(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))


def is_within(path, root):
    path = canonical(path)
    root = canonical(root)
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def fast_within(path_key, root_key):
    return path_key == root_key or path_key.startswith(root_key + os.sep)


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    return f"{size / 1024 / 1024 / 1024:.2f} GB"


def user_profiles():
    users_root = os.path.join(SYSTEM_DRIVE, "Users")
    if not os.path.isdir(users_root):
        return []
    result = []
    try:
        for item in os.scandir(users_root):
            if item.is_dir(follow_symlinks=False):
                result.append(item.path)
    except OSError:
        pass
    return result


def approved_roots():
    """返回明确允许清理的目录，目录本身永远不删除。"""
    roots = []
    seen = set()
    windir = os.environ.get("WINDIR", os.path.join(SYSTEM_DRIVE, "Windows"))

    def add(path):
        if not os.path.isdir(path) or os.path.islink(path):
            return
        key = fast_key(path)
        if key not in seen:
            seen.add(key)
            roots.append(path)

    add(os.path.join(windir, "Temp"))
    browser_data = [
        ("Google", "Chrome", "User Data"),
        ("Microsoft", "Edge", "User Data"),
        ("BraveSoftware", "Brave-Browser", "User Data"),
        ("Vivaldi", "User Data"),
        ("Opera Software", "Opera Stable"),
    ]
    cache_names = ("Cache", "Code Cache", "GPUCache")

    for profile in user_profiles():
        local = os.path.join(profile, "AppData", "Local")
        roaming = os.path.join(profile, "AppData", "Roaming")
        add(os.path.join(local, "Temp"))

        for parts in browser_data:
            browser_root = os.path.join(local, *parts)
            if not os.path.isdir(browser_root) or os.path.islink(browser_root):
                continue
            try:
                browser_profiles = list(os.scandir(browser_root))
            except OSError:
                continue
            for browser_profile in browser_profiles:
                if not browser_profile.is_dir(follow_symlinks=False):
                    continue
                for cache_name in cache_names:
                    add(os.path.join(browser_profile.path, cache_name))

        firefox_root = os.path.join(local, "Mozilla", "Firefox", "Profiles")
        if os.path.isdir(firefox_root) and not os.path.islink(firefox_root):
            try:
                for firefox_profile in os.scandir(firefox_root):
                    if firefox_profile.is_dir(follow_symlinks=False):
                        add(os.path.join(firefox_profile.path, "cache2"))
            except OSError:
                pass

        for cache_name in cache_names:
            add(os.path.join(roaming, "discord", cache_name))
    return roots


def known_shell_cache(path_key, path, users_root_key):
    name = os.path.basename(path).lower()
    parent = os.path.basename(os.path.dirname(path)).lower()
    return (fast_within(path_key, users_root_key)
            and parent == "explorer"
            and (name.startswith("thumbcache_") or name.startswith("iconcache_"))
            and name.endswith(".db"))


def classify_file(path, root_specs, users_root, users_root_key):
    """只返回高置信度垃圾，未知文件返回 None。"""
    name = os.path.basename(path)
    extension = os.path.splitext(name)[1].lower()
    if extension in BLOCKED_EXTENSIONS:
        return None
    path_key = fast_key(path)

    for root, root_key, is_temp in root_specs:
        if not fast_within(path_key, root_key):
            continue
        if is_temp:
            if extension in TEMP_EXTENSIONS or name.startswith("~"):
                return root, "临时文件/日志文件"
        else:
            return root, "浏览器或软件缓存"

    if known_shell_cache(path_key, path, users_root_key):
        return users_root, "Windows 缩略图缓存"
    return None


def scan_tree(root_path, root_node, root_specs, users_root, cancel_event, progress):
    """递归建立大小树；只读文件元数据，不打开文件内容。"""
    processed = 0
    total_size = 0
    candidates = []
    last_update = 0
    users_root_key = fast_key(users_root)

    def walk(path, node):
        nonlocal processed, total_size, last_update
        try:
            entries = os.scandir(path)
        except (OSError, PermissionError):
            return
        try:
            for entry in entries:
                if cancel_event.is_set():
                    return
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        child = DirNode(entry.path, entry.name)
                        node.children.append(child)
                        walk(entry.path, child)
                        node.size += child.size
                        node.files += child.files
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    node.size += info.st_size
                    node.files += 1
                    processed += 1
                    total_size += info.st_size
                    classified = classify_file(entry.path, root_specs, users_root,
                                               users_root_key)
                    if classified:
                        safe_root, reason = classified
                        candidates.append(Candidate(entry.path, safe_root, reason,
                                                    info.st_size, info.st_mtime))
                    now = time.time()
                    if now - last_update > 0.2:
                        last_update = now
                        progress(processed, total_size, entry.path)
                except (OSError, PermissionError):
                    continue
        finally:
            entries.close()

    walk(root_path, root_node)
    return processed, total_size, candidates, cancel_event.is_set()


class SafeCleaner:
    def __init__(self, root):
        self.root = root
        self.root.title("C 盘空间分析与安全清理工具")
        self.root.geometry("1280x760")
        self.root.minsize(900, 560)
        self.scanning = False
        self.cancel_event = threading.Event()
        self.dir_root = None
        self.all_nodes = []
        self.candidates = []
        self.dir_iids = {}
        self.search_iids = {}
        self.clean_iids = {}
        self.status = StringVar(value="准备扫描 C 盘")
        self.search_text = StringVar()
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")
        self.scan_button = ttk.Button(top, text="扫描 C 盘", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(top, text="取消扫描", command=self.cancel_scan,
                                        state="disabled")
        self.cancel_button.pack(side="left", padx=6)
        ttk.Label(top, text="搜索目录或文件路径:").pack(side="left", padx=(24, 5))
        ttk.Entry(top, textvariable=self.search_text, width=42).pack(side="left")
        ttk.Button(top, text="搜索", command=self.search).pack(side="left", padx=4)
        ttk.Button(top, text="清除搜索", command=self.clear_search).pack(side="left")

        self.progress = ttk.Progressbar(self.root, mode="determinate", maximum=100)
        self.progress.pack(fill="x", padx=10, pady=(0, 5))
        ttk.Label(self.root, textvariable=self.status).pack(fill="x", padx=10, pady=(0, 8))

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=10)
        self._build_space_tab()
        self._build_search_tab()
        self._build_clean_tab()

    def _build_space_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="空间占用")
        columns = ("size", "files", "path")
        self.dir_tree = ttk.Treeview(frame, columns=columns, show="tree headings")
        self.dir_tree.heading("#0", text="目录")
        self.dir_tree.heading("size", text="大小")
        self.dir_tree.heading("files", text="文件数")
        self.dir_tree.heading("path", text="完整路径")
        self.dir_tree.column("#0", width=300, anchor="w")
        self.dir_tree.column("size", width=130, anchor="e")
        self.dir_tree.column("files", width=100, anchor="e")
        self.dir_tree.column("path", width=650, anchor="w")
        self.dir_tree.pack(fill="both", expand=True)
        self.dir_tree.bind("<<TreeviewOpen>>", self._expand_directory)
        self.dir_tree.bind("<Double-1>", self._open_directory)

    def _build_search_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="搜索结果")
        columns = ("type", "size", "files", "path")
        self.search_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, title in (("type", "类型"), ("size", "大小"),
                           ("files", "文件数"), ("path", "完整路径")):
            self.search_tree.heading(col, text=title)
        self.search_tree.column("type", width=120)
        self.search_tree.column("size", width=130, anchor="e")
        self.search_tree.column("files", width=100, anchor="e")
        self.search_tree.column("path", width=850)
        self.search_tree.pack(fill="both", expand=True)
        self.search_tree.bind("<Double-1>", self._open_search_result)

    def _build_clean_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="可清理垃圾")
        columns = ("reason", "size", "modified", "path")
        self.clean_tree = ttk.Treeview(frame, columns=columns, show="headings",
                                       selectmode="extended")
        for col, title in (("reason", "类型"), ("size", "大小"),
                           ("modified", "最后修改"), ("path", "完整路径")):
            self.clean_tree.heading(col, text=title)
        self.clean_tree.column("reason", width=180)
        self.clean_tree.column("size", width=120, anchor="e")
        self.clean_tree.column("modified", width=160, anchor="center")
        self.clean_tree.column("path", width=820)
        self.clean_tree.pack(fill="both", expand=True)
        self.clean_tree.bind("<Double-1>", self._open_clean_result)

        buttons = ttk.Frame(frame, padding=8)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="全选可清理文件", command=self.select_all_clean) \
            .pack(side="left")
        self.delete_button = ttk.Button(buttons, text="删除选中垃圾",
                                         command=self.confirm_delete, state="disabled")
        self.delete_button.pack(side="left", padx=6)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.cancel_event.clear()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.delete_button.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)
        self.status.set("正在扫描 C 盘目录和文件大小...")
        self._clear_views()
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def cancel_scan(self):
        if self.scanning:
            self.cancel_event.set()
            self.status.set("正在停止扫描...")

    def _clear_views(self):
        self.dir_tree.delete(*self.dir_tree.get_children())
        self.search_tree.delete(*self.search_tree.get_children())
        self.clean_tree.delete(*self.clean_tree.get_children())
        self.dir_iids.clear()
        self.search_iids.clear()
        self.clean_iids.clear()
        self.dir_root = None
        self.all_nodes = []
        self.candidates = []

    def _scan_worker(self):
        try:
            roots = approved_roots()
            root_specs = [(root, fast_key(root),
                           os.path.basename(root).lower() == "temp")
                          for root in roots]
            users_root = os.path.join(SYSTEM_DRIVE, "Users")
            root_node = DirNode(SCAN_ROOT, SCAN_ROOT)
            processed, total_size, candidates, cancelled = scan_tree(
                SCAN_ROOT, root_node, root_specs, users_root,
                self.cancel_event,
                lambda count, size, path: self.root.after(
                    0, self._update_progress, count, size, path))
            self.root.after(0, self._scan_done, root_node, candidates,
                            processed, total_size, cancelled)
        except Exception as exc:
            self.root.after(0, self._scan_error, str(exc))

    def _update_progress(self, count, total_size, path):
        self.status.set(f"扫描中：已检查 {count} 个文件，已统计 {format_size(total_size)}，当前 {path}")

    def _scan_done(self, root_node, candidates, processed, total_size, cancelled):
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100, value=100)
        self.scanning = False
        self.cancel_button.configure(state="disabled")
        self.scan_button.configure(state="normal")
        self.dir_root = root_node
        self.all_nodes = []
        self._collect_nodes(root_node)
        self._show_directory_root()
        self.candidates = sorted(candidates, key=lambda item: item.size, reverse=True)
        self._show_clean_results()
        state = "已取消" if cancelled else "扫描完成"
        self.status.set(
            f"{state}：检查 {processed} 个文件，占用 {format_size(total_size)}；"
            f"发现 {len(self.candidates)} 个明确可清理文件"
        )
        self.delete_button.configure(state="normal" if self.candidates else "disabled")

    def _scan_error(self, error):
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.scanning = False
        self.cancel_button.configure(state="disabled")
        self.scan_button.configure(state="normal")
        self.status.set("扫描失败")
        messagebox.showerror("扫描失败", error)

    def _collect_nodes(self, node):
        self.all_nodes.append(node)
        for child in node.children:
            self._collect_nodes(child)

    def _node_values(self, node):
        return format_size(node.size), str(node.files), node.path

    def _show_directory_root(self):
        if not self.dir_root:
            return
        iid = "dir_root"
        self.dir_iids[iid] = self.dir_root
        self.dir_tree.insert("", "end", iid=iid, text=self.dir_root.name,
                             values=self._node_values(self.dir_root), open=False)
        self._add_dummy(iid, self.dir_root)

    def _add_dummy(self, iid, node):
        if node.children:
            self.dir_tree.insert(iid, "end", iid=iid + "_dummy", text="加载目录...")

    def _expand_directory(self, event=None):
        iid = self.dir_tree.focus()
        node = self.dir_iids.get(iid)
        if not node or iid + "_loaded" in self.dir_iids:
            return
        for child_iid in self.dir_tree.get_children(iid):
            self.dir_tree.delete(child_iid)
        for index, child in enumerate(sorted(node.children,
                                             key=lambda item: item.size,
                                             reverse=True)):
            child_iid = f"{iid}_{index}"
            self.dir_iids[child_iid] = child
            self.dir_tree.insert(iid, "end", iid=child_iid, text=child.name,
                                 values=self._node_values(child), open=False)
            self._add_dummy(child_iid, child)
        self.dir_iids[iid + "_loaded"] = node

    def _open_directory(self, event=None):
        node = self.dir_iids.get(self.dir_tree.focus())
        self._open_path(node.path if node else None)

    def search(self):
        query = self.search_text.get().strip().lower()
        self.search_tree.delete(*self.search_tree.get_children())
        self.search_iids.clear()
        if not query:
            self.tabs.select(1)
            return
        matches = [node for node in self.all_nodes if query in node.path.lower()]
        for index, node in enumerate(sorted(matches, key=lambda item: item.size,
                                            reverse=True)[:1000]):
            iid = f"search_{index}"
            self.search_iids[iid] = node
            self.search_tree.insert("", "end", iid=iid,
                                    values=("目录", format_size(node.size),
                                            str(node.files), node.path))
        self.tabs.select(1)
        self.status.set(f"搜索到 {len(matches)} 个目录，显示前 {min(len(matches), 1000)} 个")

    def clear_search(self):
        self.search_text.set("")
        self.search_tree.delete(*self.search_tree.get_children())
        self.search_iids.clear()

    def _open_search_result(self, event=None):
        node = self.search_iids.get(self.search_tree.focus())
        self._open_path(node.path if node else None)

    def _show_clean_results(self):
        self.clean_tree.delete(*self.clean_tree.get_children())
        self.clean_iids.clear()
        for index, item in enumerate(self.candidates):
            iid = f"clean_{index}"
            self.clean_iids[iid] = item
            modified = datetime.fromtimestamp(item.mtime).strftime("%Y-%m-%d %H:%M")
            self.clean_tree.insert("", "end", iid=iid,
                                   values=(item.reason, format_size(item.size),
                                           modified, item.path))

    def _open_clean_result(self, event=None):
        item = self.clean_iids.get(self.clean_tree.focus())
        self._open_path(os.path.dirname(item.path) if item else None)

    def _open_path(self, path):
        if not path or not os.path.exists(path):
            return
        try:
            os.startfile(path)
        except (AttributeError, OSError) as exc:
            messagebox.showerror("打开失败", str(exc))

    def select_all_clean(self):
        self.clean_tree.selection_set(self.clean_tree.get_children())

    def confirm_delete(self):
        selected = [self.clean_iids[iid] for iid in self.clean_tree.selection()
                    if iid in self.clean_iids]
        if not selected:
            messagebox.showinfo("提示", "请先在“可清理垃圾”页选择文件。")
            return
        total = sum(item.size for item in selected)
        prompt = (f"准备删除 {len(selected)} 个明确缓存垃圾，约 {format_size(total)}。\n\n"
                  "只删除白名单中的文件，不删除目录、系统文件或程序文件。\n"
                  "文件不进入回收站，是否继续？")
        if messagebox.askyesno("确认删除", prompt, icon="warning"):
            self.delete_button.configure(state="disabled")
            threading.Thread(target=self._delete_worker, args=(selected,), daemon=True).start()

    def _delete_worker(self, selected):
        deleted = 0
        failed = 0
        for item in selected:
            try:
                if item.path == item.root or not is_within(item.path, item.root):
                    failed += 1
                    continue
                if os.path.islink(item.path) or not os.path.isfile(item.path):
                    failed += 1
                    continue
                info = os.stat(item.path, follow_symlinks=False)
                if info.st_size != item.size or info.st_mtime != item.mtime:
                    failed += 1
                    continue
                os.remove(item.path)
                deleted += 1
            except OSError:
                failed += 1
        self.root.after(0, self._delete_done, deleted, failed)

    def _delete_done(self, deleted, failed):
        messagebox.showinfo("清理完成", f"删除 {deleted} 个文件，失败或已变化 {failed} 个。")
        self.start_scan()


if __name__ == "__main__":
    app = Tk()
    SafeCleaner(app)
    app.mainloop()
