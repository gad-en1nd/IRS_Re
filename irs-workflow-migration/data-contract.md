# IRS 迁移数据契约与运行器规范 (Data Contract & Runner Specification)

## 1. 目标平台与并发锁规范
- **原生 Windows 目标**：运行器以 Windows 原生环境为主目标。单写互斥锁必须在 Windows 上使用 `msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)`（或阻塞模式 `msvcrt.LK_LOCK`）实现；在可选的 POSIX 环境上 fallback 至 `fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)`。严禁假设 Linux 专有调用。
- **标准库限定**：仅使用 Python 标准库，不依赖外部进程管理器或第三方框架。

## 2. 状态源、初始快照与账本事实 (Snapshot & Single-Writer Ledger)
- **初始快照**：宿主运行器在初次初始化时一次性生成只读基线快照 `.local/initial-state.json`，后续重放与运行过程中该文件保持恒定。
- **唯一真实账本**：初始化完成后，`events.jsonl` 是系统事实的唯一数据源。状态投影由运行器根据 `.local/initial-state.json` 快照基线与后续追加的合法事件序列以纯确定性函数重新投影计算得出。
- **崩溃安全、刷盘与审计持久化**：
  - 新事件在进入状态投影前，必须先追加写入 `events.jsonl` 并显式调用 `os.fsync` 刷新刷盘；
  - 读取 `events.jsonl` 时，若遇到非完整行、截断行或 JSON 解析错误，运行器必须显式抛出不可恢复的崩溃错误 (`LedgerCorruptionError`) 并立即终止，严禁静默吞掉异常或跳过残损记录；
  - `decisions.jsonl` 每接收一个合法的 `review_result` 事件追加一条记录（按 `event_id` 去重）。在系统崩溃恢复或账本重放时，运行器比对已有 `event_id` 追加缺失的决策记录，严禁抹除既有审计痕迹；
  - `state.json` 的更新先写入同目录随机临时文件，刷新刷盘 (`os.fsync`) 后通过 `os.replace` 原子替换；
  - M1 阶段运行器不部署任何不可逆的外部动作分发器 (External Action Dispatcher)，严禁假装实现跨系统 Exactly-Once。

## 3. 私有信任源注册表 (.local/trusted-sources.json)
外部调用传入的凭据路径或文本声明 `approved: true` 一律不构成授权。授权唯一依据是受保护的私有注册表 `.local/trusted-sources.json`。该注册表由宿主环境所有者从真实人类授权或审查凭证初始化。

当前上层工具边界配置已排除 `.local` 路径，但原生操作系统级别的写/运行硬隔离尚未建立证明。在启用工具写/运行前必须具备经证明的硬性 OS 保护，当前系统严禁宣称已具备完全硬沙箱拦截能力。

### 3.1 注册表格式
```json
{
  "schema_version": 1,
  "sources": {
    "migration-start": {
      "actor": "human",
      "scope": "migration",
      "policy_id": "USER-MIGRATION-M1-START-20261002",
      "event_types": ["submit_task", "pause", "bind_roles", "cutover"],
      "evidence_ref": "human-authorization.json",
      "evidence_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    "review-REQ-ILLUSTRATIVE-UNSIGNED": {
      "actor": "ChatGPT",
      "scope": "migration",
      "event_types": ["review_result"],
      "request_id": "REQ-ILLUSTRATIVE-UNSIGNED",
      "candidate": {
        "commit": null,
        "tree": null,
        "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "evidence_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "scope": "migration"
      },
      "evidence_ref": "evidence/review-provenance-REQ-ILLUSTRATIVE.json",
      "evidence_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}
```
*(注：上文 `review-REQ-ILLUSTRATIVE-UNSIGNED` 仅为未签名示意示例，非真实注册项。真实注册项由宿主环境在人类授权或 GPT 独立签署后写入)*

### 3.2 验证准则
- 注册表记录是对不可变证据文件的只追加引用 (append-only)；若对同一 `request_id` 提交了新候选，必须分配新的审查源注册项或版本凭证引用，严禁就地覆写旧候选审查源；
- 事件中的 `source_ref` 必须是注册表 `sources` 中存在的标识符 ID，不得为任意文件系统路径；
- 运行器比对注册项的 `actor`、`scope`、`event_types`、目标 `request_id` 及实际私有证据哈希 (`evidence_hash`)；
- 注册表由宿主环境所有者受信管理，本系统不伪称实现对未认证操作者的密码学公钥用户身份认证。

## 4. 事件封包契约与指纹 (Event Envelope)

### 4.1 封包格式
```json
{
  "event_id": "EVT-YYYYMMDD-UUID",
  "event_type": "submit_task | review_result | task_completed | pause | bind_roles | cutover",
  "request_id": "REQ-YYYYMMDD-UUID",
  "scope": "migration | business",
  "payload": {},
  "source_ref": "migration-start"
}
```

### 4.2 规范事件指纹 (Canonical Fingerprint) 与冲突判定
- **项目规范指纹**：使用项目约定的 Python 标准库确定性序列化规则生成 UTF-8 字节并计算 SHA-256 哈希：
  ```python
  canonical_bytes = json.dumps(
      event,
      ensure_ascii=False,
      sort_keys=True,
      separators=(',', ':'),
      allow_nan=False
  ).encode('utf-8')
  fingerprint = 'sha256:' + hashlib.sha256(canonical_bytes).hexdigest()
  ```
  本实现限定标准库内建能力，不声明依赖 RFC 8785 外部标准库依赖。
- **幂等与冲突处理**：
  - 若接收到的 `event_id` 已在账本中存在：
    - 若新事件与账本中已有事件的规范指纹完全一致，运行器视为重复提交 (Duplicate)，保持幂等无害跳过；
    - 若新事件与账本中已有事件字段或规范指纹不一致，运行器立即拒绝并抛出 `EventConflictError`。

## 5. 事件载荷定义与状态机规则

### 5.1 `candidate` 身份五元组
每个提议必须包含绑定五元组：
```json
{
  "commit": null,
  "tree": null,
  "content_hash": "sha256:[a-f0-9]{64}",
  "evidence_hash": "sha256:[a-f0-9]{64}",
  "scope": "migration"
}
```
- Pre-Git 阶段文本候选：`commit` 与 `tree` 必须均为 `null`；Git 阶段启用时必须为 40 位小写十六进制字符串；
- `content_hash` 与 `evidence_hash` 必须为合法 `sha256:64hex` 字符串。

### 5.2 最小事件载荷定义
1. **`submit_task`**
   - Payload: `{"candidate": <candidate_identity>, "task": {"task_id": "TASK-...", ...}}`
   - 状态流转：
     - 若同一 `request_id` 再次提交且 `candidate` 内容完全未变，保留已有审批状态，不重置为 `NEEDS_REVIEW`；
     - 若同一 `request_id` 提交了不同的 `candidate` 哈希，系统创建新版本修订，并将审查状态重置为 `NEEDS_REVIEW`，既有旧审查结论立即失效。
2. **`review_result`**
   - Payload: 严格遵循 `decision-output.schema.json`。
   - 规则：
     - `authorization_source_ref` 必须指向 `.local/trusted-sources.json` 中的审查注册项，且与封包的 `source_ref` 一致；
     - `review_kind` 仅限 `technical` 或 `agent_visual`，严禁标注为 `human_visual`；
     - `human_approval` 必须为 `false`；
     - 若 `review_kind = technical` 缺少证据或证据失效，决策不得为 `approve`；
     - 若 `review_kind = agent_visual`，必须包含明确且真实捕获的图像路径及哈希，否则决策必须为 `needs_evidence`。
3. **`task_completed`**
   - Payload: `{"candidate": <candidate_identity>}`
   - 规则：
     - 提交的候选身份必须与当前 `request_id` 最新且已处于 `approve` 状态的候选五元组完全一致；
     - 若针对已处于过期 (stale) 或被拒绝 (reject) 候选尝试标记完成，运行器拒绝并抛出异常；
     - 重复收到的已完成事件幂等忽略，不触发多余动作。
4. **`pause`**
   - Payload: `{"reason": "string", "policy_id": "USER-POLICY-..."}`
   - 规则：作用范围受 `scope` 严格约束 (如 `scope = migration` 仅暂停迁移)。系统严禁引入任何业务恢复 (`business_resume`) 接口。
5. **`bind_roles`**
   - Payload: `{"roles": {"overview": {"thread_id": "actual-id", "status": "candidate"}, ...}}`
   - 规则：`overview`、`approval`、`acceptance` 割接前必须提供经验证的真实非空 `thread_id`；`ad_hoc` 在具体交付任务需要前允许保持待命按需 (`pending/on_demand`) 状态。
6. **`cutover`**
   - 规则：来源必须具备人类实际授权证据注册项；Payload 必须包含经验证的审查验收产物引用与对应哈希，且所有适用门禁处于 PASS 状态 (拒绝裸布尔变量标记)；
   - **V05 隔离门禁**：在获得宿主原生 OS 写/运行隔离硬证明前，`write_run_tools_enabled` 必须保持 `false`，门禁 `V05` 保持 BLOCKED。此阻塞阻止全量工具接管割接，既有的受控文本补丁审查路径保持不变。无需声称 OS 沙箱不可行或已完全实现。