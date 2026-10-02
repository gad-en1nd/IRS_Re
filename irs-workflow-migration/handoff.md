# IRS 迁移交接报告 (M1 阶段)

## 1. 版本状态与授权基线
- **版本状态**：当前正式版本 B04/v0.4.0；最新业务停止 USER-POLICY-PAUSE-AFTER-B04-20261002-001 覆盖旧自主推进 USER-POLICY-AUTONOMOUS-001 和旧恢复 USER-POLICY-RESUME-20261002-001 的后续业务接续，heartbeat irs 为 PAUSED，不启动 B05；迁移授权 USER-MIGRATION-M1-START-20261002 允许迁移建设、必要角色创建/内部沟通和经审核上传，不能恢复业务。06_B05 仅交接准备，未启动版本；过时 active/额度截止不是恢复指令。
- **基线标识**：`request_id: IRS-WORKFLOW-M1-001`，业务状态已暂停 (`business_paused: true`)。
- **Git 锚点**：Commit `279152ce084d587f197d6def1afa7fb20c9d1e21`，Tree `d93af31e8ecc71bc09bf819e0ed929726fe11ad3`，附注标签 Tag `987bafc75c25cdce5211a2df55ac4c97b8515129` (`B04-RELEASE-001-R2`)。
- **控制文件摘要与指纹**：
  - `manifest.json` SHA256: `660376d4031f693d28cdd2a8710bf6433ca1df2a6d592cbd08a0808adde0fb85`
  - `handout.md` SHA256: `7f309847fff30fca2101a82c85bdaabc47b4b39db707ffd3d708d8d3fd00cdd7`
  - 原 00 生成之规范交接文档已私有归档 SHA256: `9a47315cbeefb111c71b055669c198651d85f835333ac309088b605af6fb3e6e`
  - 详细基线字段索引见 `acceptance/V01-baseline.json`。

## 2. 历史验收事实与证据溯源
- **历史测试事实**：前期 930 个历史文件及 25 处真实捕获截图已在交付阶段完成完整核验；本次迁移仅执行基线身份与完整性核对，未重复执行全量测试。
- **关键证据与权限溯源路径**：
  - API 验收日志：`evidence/test-b04-api-review-02-out.log` (4/4)
  - Web 验收日志：`evidence/test-b04-web-review-out.log` (4/4)
  - 只读 Web 核验：2/2
  - B03 兼容核验：1/1
  - 历史环境关停证据：`env003-final-stop-proof.json`

## 3. 当前环境、进程与工具事实
- **数据库与进程声明**：本次迁移没有启动数据库；历史 ENV003 有最终停止证据；本次未检查全机当前进程，不能断言当前没有数据库进程。
- **工作区未跟踪文件**：`apps/work/` 仅为历史构建静态只读产物，非业务源码。
- **工具验证现状**：只读工具仅在单测试文件两轮交互中通过 723 tokens 探测，未开通全量工具集。

## 4. 业务契约继承与已知约束索引 (面向 New00)
- **继承业务契约**：
  1. `students.id` 身份标识在招生与就业模块间统一复用规范；
  2. 多租户与对象级权限隔离机制；
  3. 共享资源目录访问权限隔离；
  4. 服务端鉴权 PDF 文件安全访问；
  5. 数据库迁移采用向前兼容的 expand 方式，回退保留新增数据及外键，不执行删除列或 down migration；
  6. B03 无法直接读取 B04 历史就业数据的向下兼容边界。
- **已知约束与边界限制 (Known Limits)**：
  - 源码/版权/移动端/大数据量列表/自由文本隐私限制（仅限测试桩 fixture 数据，严禁接入或泄露生产数据）；
  - HTML 独立交付物已交付，但受限于宿主安全策略阻断真实浏览器渲染交互，核验挂起中 (`HTML-BROWSER-VERIFY`)。

## 5. GitHub 目标仓库状态与未知项 (Known Unknowns)
- **仓库定位**：已知目标仓库 `https://github.com/gad-en1nd/IRS_Re` (公开空仓，main 分支)。
- **凭据现状**：CLI 令牌无效；集成连接器虽显示 push 元数据权限，但实际推送返回 HTTP 403 (Resource not accessible by integration)。当前判定为写权限受阻，未上传任何内容。
- **架构重构动因**：消除全量上下文重复读取导致的配额枯竭与长程注意力耗散；以紧凑确定性决策取代超长历史记忆依赖。
- **已知未知项清单**：
  1. `writeisolation`：宿主写与执行安全沙箱方案待验证；
  2. `desktopexecbridge`：桌面执行桥接通信稳定性未知；
  3. `costs`：多角色长线运行代币与计算成本尚未收敛估算；
  4. `Githubrepo`：远程写权限凭据授权待人类用户介入修复；
  5. `HTML-BROWSER-VERIFY`：既有 HTML 交付物因安全策略阻断真实浏览器渲染交互，核验挂起中。