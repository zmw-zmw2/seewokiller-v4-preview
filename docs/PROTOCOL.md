# SKAG 通信协议规范 v1

控制台（SeewoKiller.exe）与 agent（skagent.exe）之间的指令/回执协议。
实现见 `src/sk_protocol.c`（双方共用），测试见 `tests/test_protocol.c`。

## 包格式（小端）

```
偏移  长度  内容
0     4     magic "SKAG" (0x47414B53)
4     1     协议版本 (当前 1)
5     1     消息类型: 1=指令(控制台→agent) 2=回执(agent→控制台)
6     2     JSON 长度 N
8     32    HMAC-SHA256
40    N     JSON (UTF-8, 仅扁平 key/value)
```

- 包总长 = 40 + N，N ≤ 2048。
- **签名域**：HMAC 对「整个包且 [8..40) 置零」计算——即发送方先填零再签名再填值，
  验签方同样置零后重算。这是本协议最容易写错的地方（曾因未置零导致全部验签失败）。
- 验签失败、magic/版本/长度不符：**静默丢弃**，无任何回执。

## 密钥

32 字节随机，控制台首次运行生成于 exe 同目录 `key.bin`，agent 部署时随
SFTP 一起推到 `C:\Temp\SK\key.bin`。换钥 = 重新部署双方。

## 防重放（三层）

1. `ts` 字段：UTC 秒，双方时钟差 ±900s 之外的包拒绝（回执 `ts out of window`）
2. `task_id`：agent 维护 64 项环形去重，同 id 只执行一次
3. 回包端口 `reply_port` 每任务随机，UDP 回执只发往该端口

## 通道

| | 方向 | 地址 |
|---|---|---|
| 指令 | 控制台 → 全部 agent | 组播 `239.255.17.23:47381`（TTL 4） |
| 回执 | agent → 控制台 | 单播，目的 IP=指令源，端口=JSON `reply_port` |

控制台按源 IP 去重回执（一台多条只记一次），收集窗口 2.5s。

## 指令 JSON 字段

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| task_id | int | ✓ | 任务号（时间戳随机源） |
| ts | int | ✓ | 发送时刻 |
| reply_port | int | ✓ | 回执端口 |
| targets | string | - | IP 白名单：`a.b.c.d` / `a.b.c.d-e` / 全段，逗号分隔；空=不过滤。agent 枚举本机 IPv4 不命中则静默丢弃 |
| action | string | ✓ | 见下表 |
| … | | | 各 action 的附加字段 |

### action 枚举

| action | 附加字段 | 行为 | 回执 info |
|---|---|---|---|
| ping | - | 存活探测 | `alive v<版本>` |
| exec | cmd | 桌面会话启动程序/命令（不等待） | `started` |
| exec_wait | cmd | 执行并捕获输出（≤30s） | `rc=N len=N out=...`（UTF-8 回传） |
| killmc | - | 终结 java/javaw（MC/网页游戏） | `java killed` |
| killgames | - | killmc 的历史别名，行为相同 | 同上 |
| msg | text | 桌面弹窗（text 支持中文） | `shown` |
| open_url | url | Edge 打开网页，失败回退默认浏览器 | `opened` |
| power | mode | off/reboot/logoff/lock | mode 原文 |
| isolate | allow_ip | 防火墙白名单化：只通 allow_ip（入+出），其余全断 | `isolated` |
| unisolate | - | 删白名单规则，恢复全放行基线 | `restored` |
| lockinput | text | 全屏遮罩+BlockInput 禁键鼠，text=锁屏文案 | `locked` |
| unlockinput | - | 解除禁用 | `unlocked` |

未知 action 回执 `err unknown action`。

## 回执 JSON 字段

```
task_id, host(机器名), st(ok/err), rc, info
```

`rc` 对 exec_wait 为进程退出码；其余 action 恒 0，失败时 st=err。

## 设计取舍记录

- **UDP 组播 + 小回执**：不建连、无状态，几十台并发回包无风暴（<200B/包）；
  代价是不保证送达——校园局域网丢包概率极低，且 task_id 去重使「控制端重发」
  天然幂等（当前未启用重发，需要时加两次重发即可）。
- **HMAC 而非非对称签名**：控制台与 agent 同钥部署（SFTP 通道本身已认证），
  威胁模型只防「伪造指令/重放」，不防密钥持有者作恶。
- **targets 过滤依赖 getaddrinfo(gethostname)**：主机名解析异常的机器会静默
  不响应（部署成功但不在线的排查入口）。
- **不做序列号/确认重传**：还原卡运维模型下，指令失败重发一次的成本接近零。
