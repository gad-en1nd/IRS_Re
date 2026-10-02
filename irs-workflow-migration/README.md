# IRS 工作流迁移项目 (irs-workflow-migration)

## 项目定位
本项目为独立新增的工作流迁移工程目录，用于承接与重构 IRS 相关工作流，与历史业务代码物理解耦。当前迁移路由已生效（m1-active），业务保持暂停。旧自动化为 PAUSED，B05 未启动；未做全机进程普查。人类用户当前仅授权进行工程迁移及经审核后的上传操作。

## 节点执行状态

| 节点编号 | 节点名称与职责 | 状态 |
| :--- | :--- | :--- |
| P0 | baseline/evidence | PASS_NODE_LOCAL |
| P1 | handoff/roles/rules | PASS_NODE_LOCAL |
| P2 | state/events/decisions/task contracts | PASS_NODE_LOCAL |
| P3 | runner | PASS_NODE_LOCAL |
| P4 | Gemini+GPT adapters | PASS_NODE_LOCAL |
| P5 | role entry/handoff validation | PASS_CANDIDATE_LOCAL; activated by P6 |
| P6 | paused cutover | PASS_PAUSED_CUTOVER |
| P7 | metrics/optional tuning | PASS_OBSERVATIONS; V10 BLOCKED; C16 optional not applied |

## 执行协作模型
1. **Gemini 生成候选文本**：生成符合接口契约的补丁或文本候选方案，不直接执行写入。
2. **GPT 独立审查**：对照安全边界与验收规范进行独立审查并输出结论。
3. **受控应用**：审查通过后方可在受控环境下应用补丁。
4. **真实校验**：执行确定性静态检查与真实测试，禁止无证据声称通过。
5. **本地提交**：形成具备可追溯历史的 Git 提交记录（Git 提交记录为可审计追溯历史，非绝对不可变）。
6. **远程推送**：目标仓库为 https://github.com/gad-en1nd/IRS_Re ，交付目录为 irs-workflow-migration/。每个节点通过 GPT 审核与真实检查后上传，实际远端结果另行记录。

## 隔离与凭据规范
- `.local/` 为项目局部忽略目录（非全局配置），用于存放本地私有备份、模型 Prompt、原始回复与补丁候选件，严禁纳入版本控制或上传。
- 公开凭据仅允许包含可移植校验和（SHA-256）、状态标识、审核结论与脱敏度量指标。
- 严禁提交绝对路径、本地用户名、完整用户对话、API Key 或认证凭据。

## 当前验收边界
P0–P6 的迁移建设与暂停路由切换已审核；P7 的实测记录与比较协议已交付。V01–V09 凭证仅适用于 M1 控制与路由切换，不能替代 B04 产品视觉验收。V10 因缺少同范围、同质量的完整任务前后基准而阻塞。没有恢复业务、启用 B05 或开启通用业务工具。
