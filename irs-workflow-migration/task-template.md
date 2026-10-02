# IRS 迁移任务契约模板 (Task Contract Template)

> 规范提示：本模板为未签名规范示例 (Illustrative Unsigned Example)，不构成实际执行授权。

## 1. 任务基本元数据
- **task_id**: "TASK-M1-YYYYMMDD-XXX"
- **request_id**: "REQ-YYYYMMDD-XXX"
- **scope**: "migration" <!-- 仅允许 'migration' 或 'business'，M1 阶段业务请求直接拒绝 -->
- **provenance_source_ref**: "migration-start" <!-- 对应 .local/trusted-sources.json 注册项 ID -->
- **effective_pause_policy**: "USER-POLICY-PAUSE-AFTER-B04-20261002-001"
- **environment_deadline**: null <!-- 除非真实批准的环境需要，否则保持 null -->

## 2. 路径访问白名单 (严格相对路径)
- **allow_read_paths**:
  - "./roles-and-routing.md"
  - "./workflow-amendment-M1.md"
  - "./data-contract.md"
  - "./state.json"
- **allow_write_paths**:
  - "./candidate-patch.diff"

## 3. 语义化命令集 (禁止任意 Shell，写执行工具当前硬禁用)
- **allowed_semantic_commands**:
  - `inspect_diff` <!-- 只读对比 -->
  - `validate_schema` <!-- 离线模式校验 -->
- **tool_execution_status**: BLOCKED (write_run_tools_enabled = false)

## 4. 架构设计与契约约束引用
- 继承契约: `roles-and-routing.md`, `workflow-amendment-M1.md`, `data-contract.md`
- 冻结原则: 禁止直接修改产品业务源码，禁止启动 B05，禁止跨越租户与数据库约束。

## 5. 验收标准 (Acceptance Criteria, AC)
- AC-1: 实现必须输出纯文本候选，由 `content_hash` 与 `evidence_hash` 强绑定。
- AC-2: 独立审查由 GPT Reviewer 基于紧凑上下文执行，禁止混入 Gemini 工具历史。
- AC-3: 若涉及视觉审查，必须绑定真实捕获截图相对路径与内容哈希，拒绝模拟伪造日志。

## 6. 输入上下文载荷
<!-- 仅注入当次任务紧凑必要上下文，不得注入全量历史会话 -->
```json
{
  "task_id": "TASK-M1-YYYYMMDD-XXX",
  "input_summary": "...",
  "real_image_paths": []
}
```
