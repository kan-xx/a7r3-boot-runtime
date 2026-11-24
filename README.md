# `a7r3-boot-runtime` — 索尼 A7R III (FW 3.10) 模块注册扩展、双槽启动守护与事务化部署底座

`a7r3-boot-runtime` 是面向 **Sony Alpha 7R III (`ILCE-7RM3`, 固件版本 `3.10`)** 的机内常驻运行时与事务部署底座，覆盖开机早期守护、主进程 `im.elf` 模块注册扩展、电源休眠与唤醒（`INACT / ACT`）屏障同步、可选扩展分块自加载、`DT_FINI` 顺序析构以及只读文件系统的原子事务发布。

> [!IMPORTANT]
> **净室构建声明**：本仓库仅包含独立编写的 C、POSIX Shell 与 Python 源码及宿主机离线测试，不包含任何受版权保护的原厂固件镜像、ELF/DSO 二进制或内核模块。任何基于实机解包目录的锚点校验与交叉编译均通过环境变量 `A7R3_FW_ROOT` 以只读方式在外部引用。

---

## 免责声明

> 大家请以学习为目的使用本仓库⚠️⚠️⚠️⚠️，[安全研究法律边界与合规须知](./DISCLAIMER.md#法规与合规参考)
>
> 本仓库的所有内容仅供学习和参考之用，禁止用于商业用途。任何人或组织不得将本仓库的内容用于非法用途或侵犯他人合法权益。本仓库所涉及的固件分析、系统逆向与硬件接口研究技术仅用于个人合法自有设备上的学习与研究，不得用于未经授权侵入或破坏他人设备、绕过技术保护措施、提取或传播第三方专有固件或其他非法行为。对于因使用本仓库内容而引起的任何法律责任、硬件损坏（变砖）、数据丢失或保修失效，本仓库及作者不承担任何责任。使用本仓库的内容即表示您同意本免责声明的所有条款和条件。
>
> 点击查看更为详细的免责声明。[点击跳转](./DISCLAIMER.md)

---

## 设计概览

`a7r3-boot-runtime` 旨在不重刷内核分区、不修改原厂可执行代码段（`.text`）、亦不依赖主板串口或外部刷机短接器的前提下，为封闭机身提供一套可自愈的模块化常驻基础设施。系统的挂载入口仅向 `/usr/lib/libIMDB.so` 追加一段纯数据 `PT_LOAD` 描述符（`module_id = 0xfffe, group = 6`），保持原厂代码段与重定位结构原样不动，由主进程 `im.elf` 按原生生命周期回调拉起外部编译的协调器模块。

为了在无外部救砖通道的单机环境下消除持久化风险，启动链路在 `/tmp/profile` 早期阶段先于主进程拉起独立守护进程 `a7r-boot-guard`。守护进程维护双槽 SHA-256 认证事务日志（`state.a` / `state.b`），一旦监控到主进程未能在 60 秒窗口内抵达 `READY` 屏障或收到显式故障报告，即自动将 `libIMDB.so` 原子切回原厂备份；同时针对拔除电池导致的单次冷启动中断实现了严格受限的跨纪元重试判定。在文件替换层面，原子发布器在 `renameat()` 覆盖前先通过硬链接保留活跃映射底层 inode 的引用计数（`nlink >= 1`），保证 `/usr` 分区在任何在线更新或回滚后均可重新挂载为 `MS_RDONLY`。

在运行期调度上，协调器统一接管初始化、挂起、唤醒与退出屏障，通过外部签名清单（`A7TBM001`）解耦核心底座与上层功能模块之间的哈希循环依赖，并在系统完全就绪后以有界分块校验方式按需加载上层扩展，使音频、触控等独立业务子系统得以在隔离的故障域内安全演进。

---

## 一、核心架构与模块拓扑

```mermaid
flowchart TD
    subgraph BootShell["Linux 早期 Shell 守护层 (/etc/profile -> /tmp/profile)"]
        BG["a7r-boot-guard-v21.elf<br/>双槽 SHA-256 事务日志 (state.a / state.b)<br/>60s READY 死线 + V17 单次冷断电重试 + 运行时故障回滚"]
    end

    subgraph IM["原厂主进程 /usr/bin/im.elf"]
        IMDB["/usr/lib/libIMDB.so (纯数据 PT_LOAD 扩展)<br/>184 -> 185 描述符 (index=112, module_id=0xfffe, group=6)<br/>100% 原厂代码段字节零改动"]
        OWN["liba7r_startup_full_v14.so (Startup & Lifecycle Owner)<br/>Init / Exit / Sus / Res / Inact / Act 协调器"]
        EB["liba7r_full_exit_bridge_v14.so<br/>唯一显式 DT_FINI 桥接库 (锁定 UI/OSAL 析构顺序)"]
        BF["libproBF.so (commandBF10)<br/>RTLD_NOLOAD 只读 8 KiB 状态快照查询"]
        FA["libproFA.so (commandFA00)<br/>libsencore ProductInfo 最小 dlopen 金丝雀"]
    end

    subgraph Bundle["常驻业务子系统与可选扩展"]
        B4["4-Provider 固定包<br/>SD Refresh / Exposure Observer / Audio / Menu"]
        MAN["/usr/lib/a7r_touch_boot_v1.bin (A7TBM001)<br/>外部 128B 签名清单 (消除 Owner↔Touch 哈希环)"]
        OPT["Optional Loader (48 KiB/20ms 分块校验)<br/>仅在 phase=22 & LP_ACTIVE 时按需加载"]
    end

    BG -. "监控 ready.bin / failure-*.bin<br/>超时或显式故障则原子切回原厂 libIMDB.so" .-> IMDB
    IMDB -- "Group 6 生命周期回调" --> OWN
    OWN -- "dlopen + DT_NEEDED 锚定" --> EB
    EB -- "DT_FINI 先于 libObj/libosal 触发" --> OWN
    OWN -- "托管启动 / 电源栅栏" --> B4
    OWN -- "读取清单并分块 SHA-256 验证" --> MAN
    MAN --> OPT
    BF -. "无副作用读取 owner_report_cache" .-> OWN
```

---

## 二、目录结构说明

| 目录 / 文件 | 核心职责与对应工程组件 |
|---|---|
| `imdb-registry/` | 纯数据 `libIMDB.so` `PT_LOAD` 扩展器 (`build_imdb.py`)。零外部依赖解析 ELF32，在 `group 7` 前插入 `module_id=0xfffe` (`group=6`)，保持 `.text`/`.plt`/`.rel.plt` 100% 原样且保证 `DT_REL + DT_RELSZ == DT_JMPREL`。 |
| `boot-guard/` | 独立双槽启动与运行时守护进程 (`a7r-boot-guard-v21.elf` + `/tmp/profile`) 及离线日志解码器 (`journal_decode.py`)，集成 **V17 窄化单次冷启动重试修复**。 |
| `startup-owner/` | 常驻启动与电源协调器 (`liba7r_startup_full_v14.so` + `libproBF.so`) 完整源码树，按职责划分为 `core/`、`platform/`、`bootstrap/`、`bundle/`、`barrier/`、`lifecycle/`、`autoload/` 与 `include/`。 |
| `exit-bridge/` | 进程级延迟析构桥 (`liba7r_full_exit_bridge_v14.so`)：栈中唯一携带 `DT_FINI` 的共享库，通过 `DT_NEEDED` 依赖链确保自定义线程在 Sony UI/OSAL 库卸载前安全排空并汇合。 |
| `publishers/` | 面向只读 `/usr` (`ext2`) 的原子事务发布器：`commit/` (`gi_run` 活跃映射 inode 硬链保留 + `renameat` + `MS_RDONLY` 重挂载)、`two-step-publish/`（两阶段核+封条发布器）与 `cleanup/`（零引用验证旧版本空间回收引擎）。 |
| `loader-canary/` | `libsencore.so` `ProductInfo` (`pfunc 0x10`) 进程内 `dlopen("/usr/lib/libproFA.so")` 最小无构造函数验证探针 (`commandFA00`)。 |
| `tests/` | 无需任何索尼固件二进制即可在宿主机运行的 Clang ASan/UBSan 与 Python 离线测试套件，以及可选的 `verify_firmware.py` 真机解包锚点与确定性交叉编译校验脚本。 |

---

## 三、四大关键实机故障修复与安全不变量

### 1. `ld-2.11.2.so` 非连续重定位表崩溃防护 (`DT_RELCOUNT = 0`)
索尼相机内置的旧版 `glibc ld-2.11.2.so` 在处理 `-Wl,-z,now` (`DT_BIND_NOW`) 且 `.rel.dyn` 与 `.rel.plt` 不连续的共享库时，会在第二段 (`DT_JMPREL`) 误重读 `DT_RELCOUNT` 并盲目按 `R_ARM_RELATIVE` 覆写 GOT 槽位，导致首次 PLT 调用立即 `SIGSEGV`。
- **不变量**：本仓库所有自定义 DSO 构建脚本在链接后强制将 `.dynamic` 中的 `DT_RELCOUNT` 归零，且 `imdb-registry/build_imdb.py` 严格验证 `DT_REL + DT_RELSZ == DT_JMPREL` 紧邻连续。

### 2. 已映射文件替换后的只读重挂载保护 (`nlink >= 1` 硬链保留)
Linux 内核 `fs_may_remount_ro` 在进程（如 `im.elf`）持有 `nlink == 0` 的已打开/已 `mmap` 删除态 inode 时，会拒绝将 `/usr` 重新挂载为 `MS_RDONLY` (`EBUSY`)。
- **不变量**：`publishers/commit/install.c` (`gi_run`) 与 `boot-guard/transaction.c` (`gx_run`) 在 `renameat()` 覆盖目标文件**之前**，必须先通过 `linkat()` 为当前活跃 inode 建立 `*.retained.so` 硬链接，保证替换后旧映射 inode 的 `st_nlink >= 1`，从而确保 `/usr` 100% 恢复 `MS_RDONLY`。

### 3. `startup-owner` 集成的四项核心实机修复
```mermaid
sequenceDiagram
    participant IM as im.elf 主线程
    participant WK as Owner Worker 线程
    participant K as Linux 3.0.27 / RTOS
    participant BG as a7r-boot-guard

    IM->>WK: A7R_Lifecycle_Init() (+ 可能在冷拔电池开机时抢先投递 LO_INACT)
    WK->>K: 调用 0xbd18 注册模块引用节点 (可能触发 brk 堆增长)
    Note over WK,K: 修复 #1 (error 11): bd18 返回后在持锁状态下立即调用 np_check 刷新 /proc/self/maps
    Note over WK: 修复 #3 (error 34): 队列中预存 LO_INACT 不再误判致命错误，完整接管暂停态 4-Provider 包
    WK->>K: pread64("/dev/mem", phys) 验证 RTOS 通知单例屏障
    Note over WK,K: 修复 #2 (error 37): 弃用 O_SYNC mmap2 (writecombine 导致缓存不一致)，改用线性 read_mem pread64
    IM->>WK: A7R_Lifecycle_Act() 唤醒恢复
    WK->>BG: 原子写入认证 ready.bin -> Guard 推进至 ACCEPTED
    WK->>WK: 修复 #4: 读取外部 A7TBM001 清单，每 20ms 分块校验 48 KiB，无哈希环按需自加载可选模块
```

1. **修复 #1 — `0xbd18` 引用节点分配后刷新 `/proc/self/maps` (`error 11` 修复)**：`im.elf` 的 `0xbd18` 在创建 12 字节引用节点时可能通过 `brk` 扩展堆区，使新节点落在预缓存映射表之外；`startup-owner/core/native.c` 在持有双注册信号量期间立即执行一次 `np_check(&platform)` 安全刷新。
2. **修复 #2 — `/dev/mem` `pread64` 替代 `O_SYNC mmap2` (`error 37` 修复)**：内核 `phys_mem_access_prot` 将 `O_SYNC` 映射为 `writecombine`，导致读取刚初始化的 RTOS DRAM 单例时与缓存视图分叉；`startup-owner/barrier/policy.c` 改用单次 `pread64` (`syscall 180`) 走内核线性 `MT_MEMORY` 映射并细分 `warmup.c` 阶段错误码。
3. **修复 #3 — 拔电池冷启动早期 `LO_INACT` 接管与恢复 (`error 34` 修复)**：彻底断电重上电时，原厂可能在特性 `START` 前先投递 `LO_INACT`；`native.c` 与 `bootstrap_gate.c` 将其纳入受控暂停态包接管流程，待完整排空确认并收到原厂 `LO_ACT` 后通过 `native_inact_act` 路径发布 `READY`。
4. **修复 #4 — 外部 `A7TBM001` 签名清单与 48 KiB 分块可选自加载器**：通过外部 128 字节 `a7r_touch_boot_v1.bin` 解耦 Owner 与上层触控核心库之间的双向 SHA-256 死锁环，并在 `phase == 22 && LP_ACTIVE` 时以每步 48 KiB 有界分块哈希和 `RTLD_LOCAL` 加载，任何可选模块异常仅记录诊断而不触发底包回滚。

### 4. `boot-guard` V17 窄化单次断电启动重试 (`transaction.c`)
双槽事务日志 (`state.a` / `state.b`, 256B SHA-256 认证记录) 默认在发现上一轮非 `ACCEPTED` 时立即回滚原厂 `libIMDB.so`。为防止用户在开机中途拔电池导致已验收系统被误回滚，V17 仅在满足以下**全部苛刻条件**时允许**唯一一次**新开机重试：
- 两个日志槽均完整有效且序号严格相邻 (`latest.seq == previous.seq + 1`)；
- `previous.phase == ACCEPTED(code=0)` 且 `latest.phase == STARTED(code=0)`；
- `previous.boot`、`latest.boot` 与当前 `boot_id` 三者互不相同；
- 三个 `boot_id` 下均不存在任何 `failure-<boot>.bin` 或 `.new`（含损坏文件或符号链接）。
一旦进入该次重试，新写入的 `STARTED` 会自然覆盖旧的 `ACCEPTED` 槽，若再次中断则呈现 `STARTED / STARTED`，下一轮必定 fail-closed 自动回滚原厂。

---

## 四、快速测试与构建指南

### 1. 离线宿主机单元测试（无需索尼固件、无需交叉编译器）
仅需宿主机 `clang`（支持 AddressSanitizer / UndefinedBehaviorSanitizer）与标准库 `python3`：

```bash
make test
```

`make test` 会依次执行 8 组离线验证：
1. 合成 ARM32 `ET_DYN` ELF 的 `libIMDB.so` `184 -> 185` 表扩展、零代码修改与重定位连续性验证；
2. 256 字节双槽事务日志 (`A7GXST01`) 与守护观察记录 (`observer`) 解码器边界测试；
3. `libproFA.so` `commandFA00` 协议包长、魔数与 51 种畸形输入拒绝测试；
4. `boot-guard` V21 核心事务状态机的 35 场景并发篡改、I/O 故障注入与硬链保留测试；
5. `boot-guard` V17 窄化单次重试与 `fork`/`_exit` 模拟写半截断电的 35 场景测试；
6. 冷拔电池早期 `LO_INACT -> LO_ACT` 启动门控状态机测试（631 项断言）；
7. `A7TBM001` 清单与可选加载器 `optional_loader` 预算/撤销/重入状态机测试（3,400+ 项断言）；
8. 固定 inode `/usr` 空间清理引擎与 `exit-bridge` `dlopen` 后映射刷新加载器测试。

### 2. 基于本地只读解包固件的锚点与确定性构建验证（可选）
若本地已有合法提取的 A7R III `3.10` 文件系统目录（只读访问，绝不修改原目录），可运行：

```bash
A7R3_FW_ROOT=/path/to/verified-3.10/filesystems make verify-fw
```

该命令将校验原厂关键组件 SHA-256，对真实 `libIMDB.so` 在临时目录执行纯数据扩展并核对确定性摘要（`61,840 B`），并在检测到 `zig` 编译器时自动完成全套 ARMv7 静态守护进程、常驻 Owner、退出桥与原子发布器的交叉编译及无 `RWX` / `DT_RELCOUNT == 0` 审计。

### 3. 单独调用 `libIMDB.so` 纯数据扩展器与发布身份同步工具

```bash
python3 imdb-registry/build_imdb.py \
  --stock-imdb /path/to/verified-3.10/filesystems/nflasha15/export/lib/libIMDB.so \
  --output /tmp/libIMDB.candidate.so \
  --report /tmp/imdb-report.json

# 自编译构建全套模块后，一键同步守护进程、协调器与发布器的安装随机数及摘要头文件
python3 publishers/configure_release.py \
  --artifacts-dir /path/to/your-built-artifacts
```

### 4. 清理构建产物

```bash
make clean
```

---

## 五、许可证与免责声明

本项目基于 [MIT License](LICENSE) 开源。请仔细阅读 `LICENSE` 中的商标声明与硬件安全风险提示：在未完成完整逻辑 NAND 备份并充分理解双槽回滚机制前，请勿在实机上执行任何写入操作。
