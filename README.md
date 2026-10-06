# sysinfo

Linux 系统信息检测工具（C++11）。采集语言/区域设置、内存、磁盘信息，并通过
**libclamav C API** 检测 ClamAV 查杀引擎状态、按需执行病毒扫描。

ClamAV 引擎库在首次配置时**自动安装**（无需 root）：下载发行版包并解包到
`third_party/clamav`，同时抓取官方病毒库，因此一条 `cmake -S . -B build` 即可
得到功能完整的构建。

## 构建

```sh
cmake -S . -B build -G Ninja     # 缺少 libclamav 时自动安装
cmake --build build
```

首次配置若本机没有 libclamav，会执行 `scripts/install_clamav.sh`：把
`libclamav-dev` / `libclamav12` / `libssl-dev` 解包到 `third_party/clamav`，
再从 `database.clamav.net` 下载 `main.cvd` + `daily.cvd`（约 110 MB，需联网）。
已安装则直接跳过，不会重复下载。

相关 CMake 选项：

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `SYSINFO_USE_CLAMAV` | `ON` | 关闭后不链接 libclamav，仅检测命令行版 ClamAV |
| `SYSINFO_AUTO_INSTALL_CLAMAV` | `ON` | 关闭后配置阶段不会联网安装 |
| `ClamAV_ROOT` | `third_party/clamav` | 指定 ClamAV 安装前缀 |

也可以单独运行安装脚本：

```sh
scripts/install_clamav.sh                  # 安装到 third_party/clamav
scripts/install_clamav.sh --prefix=/opt/clamav
scripts/install_clamav.sh --no-database    # 只装库，不下载病毒库
scripts/install_clamav.sh --system         # 用 apt 装到系统（需要 root）
scripts/install_clamav.sh --force          # 强制重装
```

运行时可用的环境变量：

| 变量 | 作用 |
| --- | --- |
| `SYSINFO_CLAMAV_DB` | 病毒库目录（优先于编译期默认值） |
| `CLAMAV_DATADIR` | 同上，兼容 ClamAV 习惯用法 |
| `SYSINFO_CLAMAV_CERTS` | CVD 签名校验的证书目录 |

## 使用

```sh
./build/sysinfo              # 终端下自动进入交互式界面
./build/sysinfo --plain      # 强制纯文本报告
./build/sysinfo --lang=en    # 强制英文报告（默认按 LANG/LC_* 自动检测）
./build/sysinfo --scan=/path # 使用 ClamAV 扫描指定路径
./build/sysinfo --scan=/path --remove                # 删除被感染文件
./build/sysinfo --scan=/path --quarantine=/tmp/q     # 隔离被感染文件
```

## 安全检测

`安全` 标签页展示引擎状态与扫描结果。扫描在进程内通过 libclamav C API 完成：

* `cl_init` / `cl_engine_new` / `cl_load(CL_DB_STDOPT)` / `cl_engine_compile`
  在首次使用时建立引擎，随后所有扫描复用同一个已编译引擎（病毒库只加载一次）。
* 每个文件用 `cl_scanfile_ex` 扫描，按 `cl_verdict_t` 判定；
  目录树自行递归遍历。显式指定的扫描目标若是符号链接会被跟随一次（例如
  `/lib` → `usr/lib`、`/bin` → `usr/bin`），而目录树内部的符号链接一律不跟随，
  因此链接环路不会让遍历发散。
* 遍历结束时若一个文件和一个目录都没有访问到（目标不可读、是特殊文件或链接
  失效），扫描按失败上报而不是报告“未发现病毒”，避免把没扫到东西当成干净。
* 引擎与病毒库版本来自 `cl_retver()`、`cl_engine_get_num(CL_ENGINE_DB_VERSION /
  CL_ENGINE_DB_TIME)`，签名总数来自 `cl_load` 的输出。

若构建时关闭了 libclamav，或本地没有可用病毒库，则回退到执行 `clamscan` /
`clamdscan` 子进程并解析其输出，工具在两种情况下都能正常工作。

> 说明：libclamav 在证书目录不存在时会拒绝加载病毒库（Debian/Ubuntu 默认
> `/etc/clamav/certs`）。安装脚本会在前缀下创建空证书目录，程序也会自动选择
> 一个存在的目录传给 `CL_ENGINE_CVDCERTSDIR`。

### 交互式界面（TUI）

在终端运行时默认启用；也可用 `--tui` 显式指定。使用 ANSI 转义序列与
termios 实现，不依赖 ncurses。

| 按键 | 作用 |
| --- | --- |
| `Tab` / `Shift-Tab` / `←` `→` | 切换内存 / 磁盘 / 安全 / 语言标签页 |
| `↑` `↓` / `j` `k` | 上下滚动当前标签页 |
| `s` | 启动 ClamAV 扫描（未指定目标时扫描当前目录） |
| `r` | 重新采集系统信息 |
| `q` / `Ctrl-C` | 退出 |

采集系统信息与执行扫描都在后台线程进行，界面在此期间显示旋转指示器与
进度条动画，因此不会阻塞渲染。若指定了 `--scan=<路径>`，进入界面后会自动
开始扫描。

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 仅生成报告，或扫描结果干净 |
| 1 | 扫描发现威胁 |
| 2 | 扫描无法执行 / 参数错误 |

## 目录结构

```
include/sysinfo/  公共头文件
src/              实现
  main.cpp        入口与命令行解析，纯文本报告
  tui.cpp         交互式终端界面
  report.cpp      报告内容构建（两种视图共用）
  text_table.cpp  定宽表格渲染（按终端列宽对齐，兼容 CJK）
  locale_info.cpp 区域设置 / 语言检测
  memory_info.cpp /proc/meminfo 内存信息
  disk_info.cpp   statvfs + /proc/mounts 磁盘信息
  clamav_scan.cpp libclamav C API 接入与扫描（缺库时回退到 clamscan 子进程）
  i18n.cpp        中英文文案与终端列宽计算
cmake/
  FindClamAV.cmake  定位 libclamav（含自动安装触发）
scripts/
  install_clamav.sh 无 root 安装 libclamav + 病毒库
third_party/clamav/ 自动安装产物（库、头文件、病毒库，已被 .gitignore 忽略）
```
