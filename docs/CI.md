# CI 搭建（Gitea Actions + Windows runner）

目标：协作者每次 push，runner 自动执行 `build_release.bat`
（构建 → 单元测试 → 出安装包），坏提交当场暴露。

## 前提

- Gitea ≥ 1.19 且已开启 Actions（管理后台 → 配置 → `ACTIONS_ENABLED=true`）
- 一台常开的 Windows 机器装好本项目全部构建环境（VS / CMake / vcpkg /
  Inno Setup —— 见 README「环境搭建」），这台机器就是 runner

## 注册 runner（act_runner）

1. 下载：Gitea 界面右上角「网站管理 → Actions → Runner → 创建 runner」
   页面会给出对应版本的下载命令和注册 token
2. 解压 act_runner 到例如 `C:\act_runner`，注册并连到本仓库（labels 须含
   `windows`，对应 workflow 里的 `runs-on`）：

   ```
   act_runner.exe register --instance http://192.168.1.33:30000 --token <页面给的token> --labels windows:host
   ```

3. 安装为服务（开机自启）：

   ```
   sc create gitea_runner binPath= "C:\act_runner\act_runner.exe daemon" start= auto
   sc start gitea_runner
   ```

   注意：runner 服务要以**具备构建环境的账户**运行（VS/vcpkg 装在哪个账户
   就用哪个），否则第一步找不到编译器。

4. 回到 Gitea「网站管理 → Actions」确认 runner 上线；推一个提交观察
   「Actions」页签出现 build 任务。

## 常见问题

- **job 一直排队**：labels 不匹配（workflow 是 `windows`，注册时也要含 `windows`）
- **构建失败但本机手动能过**：runner 运行账户 PATH 里没有 VS/vcpkg —— 用
  `LaunchDevCmd` 的路径检查（build_release.bat 会显式报错指认）
- **首次跑很慢**：vcpkg 若未预置缓存，runner 会现场下载 —— 把开发机的
  `downloads\`、`installed\` 整体拷给 runner 同路径即可
