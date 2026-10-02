# GPT Reviewer 决策输入上下文模板 (Decision Input Template)

> 规范说明：本模板为未签名规范示例 (Illustrative Unsigned Example)。GPT Reviewer 的独立交叉审查必须基于当次紧凑上下文输入，严禁加载全量历史对话与模型工具链调用历史。决策必须输出符合 `decision-output.schema.json` 的标准 JSON。

## 1. 契约与授权凭据引用
- **request_id**: "REQ-YYYYMMDD-XXX"
- **task_contract_ref**: "task-template.md"
- **scope**: "migration"
- **migration_policy_ref**: "USER-MIGRATION-M1-START-20261002" <!-- 顶层人类迁移授权策略引用 -->
- **authorization_source_ref**: "review-REQ-YYYYMMDD-XXX" <!-- 必须指向 .local/trusted-sources.json 中对应的 GPT 审查来源注册项 ID，不得指向 human submit 源 -->
- **effective_pause_policy**: "USER-POLICY-PAUSE-AFTER-B04-20261002-001"

## 2. 候选产物绑定元数据 (Candidate Identity)
- **candidate**:
  - **commit**: null <!-- Pre-Git 阶段必须为 null；Git 阶段启用后为 40 位 hex -->
  - **tree**: null <!-- Pre-Git 阶段必须为 null；Git 阶段启用后为 40 位 hex -->
  - **content_hash**: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - **evidence_hash**: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - **scope**: "migration"

## 3. 审查类型与验证证据
- **review_kind**: "technical" <!-- 仅限: technical | agent_visual，GPT 严禁自称 human_visual -->
- **evidence_refs**:
  - "evidence/diff-check.log"
- **real_image_paths**: [] <!-- 若 review_kind 为 agent_visual，必须提供真实截图相对路径与证据哈希 -->

## 4. 紧凑候选文本载荷 (Candidate Payload)
```diff
--- /dev/null
+++ b/target-file.ext
@@ -0,0 +1,5 @@
+... (仅包含当次提议补丁内容) ...
```

## 5. 审查判定守则
1. 输入/输出绑定的 `request_id` 与 `candidate` 必须与注册项及账本提议严格匹配；
2. 核验候选文本是否严格遵循白名单路径与数据契约；
3. 检查是否存在越权调用、未授权业务恢复 (如绕过业务暂停启动 B05)；
4. GPT 审查者不得自称 `human_visual`；人类主观视觉声明只能来自独立真实人类源；
5. `human_approval` 必须声明为 `false` (GPT 仅为自动化审查，不能伪造人类最终批准)；
6. 若 `review_kind = technical` 证据缺失或校验失败，不得批准 (`approve`)；若 `review_kind = agent_visual` 缺失实际截图文件或哈希，判定必须为 `needs_evidence`；
7. 输出结果严格遵循 `decision-output.schema.json`。