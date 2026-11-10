# CTFd source 候选静态参考 v1

覆盖本轮 Jev source 扫描输入中的 6,036 个不同源码位置：424 个 source、5,027 个非 source、585 个 unknown。
这是 AI 辅助静态规则参考，无独立人工逐点复核，不是全仓所有真实 source 的完整清单。

`annotations.jsonl` 保存位置、源码证据、标签和理由；`POLICY.md` 定义起点口径与请求读取口径；
`manifest.json` 保存仓库版本、索引、输入库存、独立入口参考、标注和规则实现的哈希。

输入库存来自 `../ctfd-source-inventory-v1`，只包含待判断位置和入口关联，不包含 source 模型答案/概率。
参考构建器不会读取 source 预测文件或 YASA source 表，数据范围仍受此前 Jev 入口选择和上下文扩展范围影响。

重建时使用新的库存和输出目录：

```bash
cd /data/fyn/yasa/YASA-Engine/LLM-check
/data/fyn/conda_envs/laya/bin/python -B build_source_reference.py inventory \
  --run runs/jev-sources-ctfd-application-v1 --out annotations/ctfd-source-inventory-custom
/data/fyn/conda_envs/laya/bin/python -B build_source_reference.py build \
  --inventory annotations/ctfd-source-inventory-custom --out annotations/ctfd-sources-static-custom
/data/fyn/conda_envs/laya/bin/python -B evaluate_source_reference.py \
  --reference annotations/ctfd-sources-static-custom --out evaluations/ctfd-jev-sources-custom
```

评测结果见 `../../evaluations/ctfd-jev-sources-static-v1/REPORT.md` 与 `NOTES.md`。
