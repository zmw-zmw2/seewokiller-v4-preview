# 更新日志

## 4.2.0（2026-10）

- lockinput/unlockinput：全屏遮罩 + BlockInput 禁用键鼠，参数可自定义锁屏文案
- killgames 更名 killmc：只杀 Java/MC，不再动 Edge；旧名保留为同行为别名
- 修复 msg/lockinput 中文双重转码导致弹窗静默失败的存量 bug
- targets 过滤：组播指令只对 IP 框范围内的机器生效（静默丢弃不命中主机）
- 版本单源化：根目录 VERSION → CMake 注入 agent，ping 回执带版本
- 工程化：协议层单元测试（ctest）、一键出包脚本、协议规范文档、CI workflow

## 4.0.0（2026-10）

- Agent 分发体系：skagent.exe（纯 C 单文件）+ 组播指令通道
- HMAC-SHA256 签名（CNG）+ 动态回包端口 + ts/task_id 防重放
- 控制台一键部署：SFTP 推 agent+密钥 → 防火墙放行 → 计划任务 ONLOGON 最高权限
- 启动自防护：防火墙开启/脱控基线/封 22+445/停 sshd/占关机位
- 上传并运行：SFTP 推送后在桌面会话直接启动（schtasks 逃逸）
- SFTP 默认路径改为用户桌面

## 3.0.0（2025）

- 批量 SSH 执行、SFTP 上传/拉取、VNC 代理（noVNC 内嵌）、插件系统（.pfl）
