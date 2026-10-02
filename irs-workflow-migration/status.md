# IRS 迁移状态报告 (M1 初始模板)

## 1. 状态性质与当前事实
- **文档性质**：本文件为初始模板，待宿主运行器 (Runner) 初始化构建派生投影；本文件不声明已被运行器渲染。
- **世代与模式**：generation = `m1-candidate`，mode = `shadow`。
- **业务暂停状态**：`business_paused = true`，生效策略为 `USER-POLICY-PAUSE-AFTER-B04-20261002-001` (B04 封板，严禁启动 B05，业务恢复处于暂停状态)。
- **迁移工程状态**：`migration_paused = false`，合法依据为迁移授权 `USER-MIGRATION-M1-START-20261002`，受信任凭证登记源 ID 为 `migration-start` (对应私有注册表 `.local/trusted-sources.json`)。
- **当前代码基线**：`B04/v0.4.0`。

## 2. 检查与审计历史状态
- **P0 阶段检查**：授权与基础基线已验证，远程目标仓库 `gad-en1nd/IRS_Re` (分支: `main`，路径: `irs-workflow-migration/`) 状态为 `AUTHORIZATION_VERIFIED_P0_P1_UPLOADED`。
- **P3 / P4 运行时检查**：`NOT_RUN` (当前尚未执行任何 P3/P4 运行时检查，亦无任何测试通过声明)。

## 3. 角色与所有权状态
- **活跃控制者**：`legacy00` (未执行割接，保持原有所有权)。
- **新角色就绪度**：
  - Overview (New00 Intake): `thread_id = null`, `status = pending_creation`
  - Stage Approval: `thread_id = null`, `status = pending_creation`
  - Version Acceptance: `thread_id = null`, `status = pending_creation`
  - Ad-hoc Delivery: `thread_id = null`, `status = pending_creation`
- **割接门禁要求说明**：割接前仅前三项入场角色 (overview, approval, acceptance) 必须绑定经验证的有效 Thread ID；ad_hoc 可保持待命按需 (`pending/on_demand`) 状态，不强制要求建立空会话。

## 4. 工具隔离与已知风险
- **工具模式**：`tool_mode = text_candidate_reviewed` (严格文本候选审查模式)。
- **自主写与执行**：`write_run_tools_enabled = false` (V05 隔离门禁当前受阻，写运行工具硬禁用)。
- **已知待决议题 (Known Issues)**：
  1. `HTML-BROWSER-VERIFY`: 真实捕获图像证据链与审查接入；
  2. `write-run-isolation`: Windows 原生/容器级写运行硬隔离待构建；
  3. `desktop-bridge`: 桌面桥接待实现；
  4. `cost-comparison`: 运营与模型开销评估。
