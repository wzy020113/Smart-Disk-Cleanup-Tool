# C 盘安全缓存清理工具

使用 `C盘安全清理工具.exe` 启动，也可以使用 `启动磁盘清理工具.bat`。

功能：

- 建立整个 C 盘的目录空间占用树，按大小排序
- 显示扫描进度、已检查文件数和累计空间
- 支持取消扫描、搜索目录路径、双击打开目录
- 单独列出可清理垃圾并支持双击查看位置
- 只有明确识别为高置信度垃圾的文件才会进入删除结果：

- 所有用户的 `AppData\\Local\\Temp`
- `C:\\Windows\\Temp` 中的临时文件
- Chrome、Edge、Brave、Vivaldi、Opera、Firefox 的明确 Cache 子目录
- Discord 的 Cache、Code Cache、GPUCache 子目录

安全限制：

- 不设置按天数删除，Temp 目录只处理明确的临时、日志和转储扩展名
- 扫描整个 C 盘，不重复进行文件统计；无权限位置自动跳过
- 结果列表支持双击打开文件所在位置
- 不处理 `Windows`、`System32`、`Program Files` 等系统文件目录
- 排除 exe、dll、sys、msi、bat、脚本等程序文件
- 删除前会再次验证路径、大小和修改时间

如果需要清理 Windows 更新、旧系统文件或回收站，请使用 Windows 自带的“存储设置”或“磁盘清理”，不要把这些目录加入本工具。
