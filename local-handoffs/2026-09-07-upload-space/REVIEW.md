# 上传空间预留与失败重试修复

2026-09-07；状态：本地已提交，已按后续明确授权推送到现有 PR #113。远程测试服务器及其虚拟机未连接、未探测。Public Ready 保持 HOLD。

## 可审核提交

- 仓库：<https://github.com/EdmundFu-233/ReCasaOS>（已通过 GitHub API 确认公开）
- 现有 Draft PR：<https://github.com/EdmundFu-233/ReCasaOS/pull/113>
- 分支：`codex/upload-space-admission`
- 原 PR 提交：`7540154d251802fc2290572125c2913c9507c559`
- 本轮提交：`11d8e38d2d9cea2693b97e2ef787efd67612ea22`
- 本轮 tree：`bbc2296b6d7ddf7b150e439e30d2bc2f624feb97`
- 独立检出：`/private/tmp/recasaos-continuation-20260907`

## 修复行为

1. v1 合并、v2 分块和合并均检查实际临时文件父目录的容量。嵌套目标挂载点的可用空间不能代替 `.temp` 所在文件系统的空间。
2. v2 所有分块落盘后，如果合并被空间预留拒绝，分块查询提示客户端重传；重传已经验证的分块会重新尝试合并。只有目标发布完成后才返回完成结果，不重复写入有效分块。
3. 分块写入被空间检查拒绝时，保留此前目录创建造成的 `changed` 状态；合并预留失败时保留分块写入错误中的持久性信息。
4. 新增 Linux 回归测试，覆盖不足空间、空间查询不可用、两个不同分块的重试、重复完成请求、实际目标内容、临时文件清理、失败后的预留释放、已记录分块被修改后的拒绝。

涉及 4 个文件：`service/file_upload.go`、`route/v1/file.go`、`service/file_upload_space_linux_test.go`、`docs/THREAT_MODEL.md`。

## 本轮验证

使用本地 Go 1.26.6：

- `go test ./pkg/filesecurity ./route/v1 ./route/v2 ./service -skip '^TestPorts$'`：通过。`TestPorts` 依赖 Linux `/proc/net`，本次 macOS 运行明确跳过。
- 上传/空间预留定向测试：通过。
- 上传/空间预留定向 `go test -race ... -count=3`：通过。
- `go vet ./pkg/filesecurity ./service ./route/v1 ./route/v2`：macOS 与 Linux amd64 编译目标均通过。
- 上述 4 个包的 Linux amd64 测试二进制交叉编译：通过。
- `git diff --check`、提交状态检查、`git bundle verify`：通过。另在独立本地检出内实际导入 bundle，恢复出的提交及 tree 与本轮结果完全相同。

新增 Linux 专用测试已经编译，尚未执行。交叉编译不是 Linux 运行证据。本机 Docker 没有运行中的 daemon；只检查过本机 Unix socket，未启动容器或连接远程 Docker。

GitHub 推送两次被自动审批拒绝。第二次已补充公开仓库和历史授权证据，但审批仍要求当前用户明确批准该提交和目标。未采用其他工具绕过拒绝。用户随后明确授权自动推送、更新及合并 PR，本轮提交已成功推送并更新 PR #113。新 CI 34132943398 的 Debian VM、特权挂载、隔离服务、浏览器测试通过；漏洞扫描和 Debian 容器包安装失败，完整 Go 测试步骤未执行。正通过既有依赖 PR #83 修复共用基线，再回到上传候选验证。此前 PR 的 CI 结果不代表本轮提交已通过。

## 恢复材料

- `11d8e38-upload-space-retry.patch`：仅本轮提交的补丁；需先具备原 PR 提交 `7540154`。
- `upload-space.bundle`：包含原 PR 提交及本轮提交；依赖 `main@f79ea30e116173d35b5a284ede44a480c025b324`，该对象已存在于主工作目录的对象库中。

即使 `/private/tmp` 检出被系统清理，也可在一个具有上述 main 基线的可写检出内导入 bundle，再切换到恢复分支：

```sh
git fetch /Users/edmundfu/Desktop/Project/ReCasaOS/local-handoffs/2026-09-07-upload-space/upload-space.bundle refs/heads/codex/upload-space-admission:refs/heads/codex/upload-space-recovered
git switch codex/upload-space-recovered
```

SHA-256：

```text
9214568907524218ab6d8e3abad4e8f6529e705d7b8734821f948eb4c8c834a7  11d8e38-upload-space-retry.patch
bd9735a9f888b666e801fbc65a68b160b0b21613fb32e663ae1ae71a722da7d9  upload-space.bundle
```

原工作目录仍在 `main@109de7e`，既有 `pkg/sambasecurity/` 草稿保留。本轮新增本目录用于本地交付；未将修复混入旧 main。
