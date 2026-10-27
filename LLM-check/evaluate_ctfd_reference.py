#!/usr/bin/env python3
"""Evaluate frozen Jev results against the selected static reference labels."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from build_ctfd_reference import FORMATIONS

HERE=Path(__file__).resolve().parent


def divide(a,b):
    return a/b if b else None


def f1(precision,recall):
    if precision is None or recall is None:
        return None
    return 2*precision*recall/(precision+recall) if precision+recall else 0.0


def percentage(value):
    return "n/a" if value is None else "{:.2%}".format(value)


def verified_annotation_digest(verification):
    """Accept the CTFd and django-helpdesk verification formats, fail closed."""
    hashes={value for value in (verification.get("artifact_sha256",{}).get("annotations.json"),
                               verification.get("annotation_sha256")) if value}
    if len(hashes)!=1:
        raise ValueError("Missing or conflicting verified annotation hashes")
    return hashes.pop()


def label_metrics(items):
    counts={label:Counter(tp=0,fp=0,fn=0,unknown=0) for label in FORMATIONS}
    for gold,prediction in items:
        expected=set(gold["formation_types"])
        verdict=prediction.get("verdict") or {}
        found=set(verdict.get("formation_types",[])) if prediction.get("status")=="success" and verdict.get("is_entrypoint") is True else set()
        raw=verdict.get("raw_formation_choices",{})
        for label in FORMATIONS:
            if label in expected and label in found:counts[label]["tp"]+=1
            if label not in expected and label in found:counts[label]["fp"]+=1
            if label in expected and label not in found:counts[label]["fn"]+=1
            if raw.get(label)=="unknown":counts[label]["unknown"]+=1
    totals=Counter()
    per_label={}
    for label,c in counts.items():
        totals.update({key:c[key] for key in ("tp","fp","fn")})
        p,r=divide(c["tp"],c["tp"]+c["fp"]),divide(c["tp"],c["tp"]+c["fn"])
        per_label[label]=dict(c,support=c["tp"]+c["fn"],precision=p,recall=r,
                              f1=divide(2*c["tp"],2*c["tp"]+c["fp"]+c["fn"]))
    p=divide(totals["tp"],totals["tp"]+totals["fp"])
    r=divide(totals["tp"],totals["tp"]+totals["fn"])
    return {"counts":dict(totals),"micro_precision":p,"micro_recall":r,
            "micro_f1":divide(2*totals["tp"],2*totals["tp"]+totals["fp"]+totals["fn"]),"per_label":per_label}


def analyze(gold_rows,prediction_rows):
    gold={r["case_id"]:r for r in gold_rows}
    if len(gold)!=len(gold_rows):raise ValueError("Duplicate ground-truth case IDs")
    predictions={r["case_id"]:r for r in prediction_rows}
    if len(predictions)!=len(prediction_rows):raise ValueError("Duplicate prediction case IDs")
    if set(predictions)-set(gold):raise ValueError("Predictions outside the ground-truth scope")
    details=[]
    for case_id,g in gold.items():
        if type(g["is_entrypoint"]) is not bool and g["is_entrypoint"] is not None:
            raise ValueError("Invalid ground-truth decision")
        p=predictions.get(case_id)
        if p and p["function"]!=g["function"]:
            raise ValueError("Target identity mismatch: "+case_id)
        v=(p.get("verdict") or {}) if p else {}
        decision=v.get("is_entrypoint") if p and p["status"]=="success" else None
        if type(decision) is not bool and decision is not None:raise ValueError("Invalid model decision")
        if g["is_entrypoint"] is None:outcome="excluded_gold_unknown"
        elif p is None:outcome="not_attempted"
        elif p["status"]!="success":outcome="request_error"
        elif decision is None:outcome="model_unknown"
        elif g["is_entrypoint"]:outcome="tp" if decision else "fn"
        else:outcome="fp" if decision else "tn"
        types=set(v.get("formation_types",[])) if p and p["status"]=="success" and decision is True else set()
        if not types<=set(FORMATIONS):raise ValueError("Unknown formation label")
        gold_types=set(g["formation_types"])
        unknown_types=[label for label,choice in v.get("raw_formation_choices",{}).items() if choice=="unknown"]
        exact=outcome=="tp" and gold_types==types and not unknown_types
        accepted_kinds=g.get("entrypoint_kinds") or ([g["entrypoint_kind"]] if g.get("entrypoint_kind") else [])
        kind_correct=outcome=="tp" and v.get("entrypoint_kind") in accepted_kinds
        details.append({"case_id":case_id,"function_id":g["function_id"],"function":g["function"],
            "file":g["file"],"start_line":g["start_line"],"gold_entrypoint":g["is_entrypoint"],
            "predicted_entrypoint":decision,"prediction_status":p["status"] if p else "not_attempted",
            "outcome":outcome,"gold_formations":g["formation_types"],"predicted_formations":sorted(types),
            "extra_formations":sorted(types-gold_types) if outcome=="tp" else [],
            "missing_formations":sorted(gold_types-types) if g["is_entrypoint"] is True else [],
            "unknown_formation_labels":unknown_types,"formation_exact":exact,
            "accepted_kinds":accepted_kinds,"predicted_kind":v.get("entrypoint_kind"),"kind_correct":kind_correct,
            "gold_subtypes":g["subtypes"],"gold_reason":g["reason"],
            "evidence_locations":["{}:{}-{}".format(e["file"],e["start_line"],e["end_line"]) for e in g["evidence"]],
            "model_consistency_issues":v.get("consistency_issues",[]),"error":p.get("error") if p else None})
    counts=Counter(r["outcome"] for r in details)
    scored=[r for r in details if r["gold_entrypoint"] is not None]
    positives=[r for r in scored if r["gold_entrypoint"] is True]
    negatives=[r for r in scored if r["gold_entrypoint"] is False]
    tp,fp,fn,tn=(counts[k] for k in ("tp","fp","fn","tn"))
    decided=tp+fp+fn+tn
    precision=divide(tp,tp+fp)
    recall=divide(tp,tp+fn)
    all_recall=divide(tp,len(positives))
    metrics={"ground_truth_total":len(gold_rows),"ground_truth_positives":len(positives),
        "ground_truth_negatives":len(negatives),"excluded_gold_unknown":counts["excluded_gold_unknown"],
        "predictions_available":len(prediction_rows),"successful_predictions":sum(p["status"]=="success" for p in prediction_rows),
        "tp":tp,"fp":fp,"fn":fn,"tn":tn,"model_unknown":counts["model_unknown"],
        "request_errors":counts["request_error"],"not_attempted":counts["not_attempted"],
        "binary_decisions_scored":decided,"decision_coverage":divide(decided,len(scored)),
        "precision":precision,"recall_on_decided_positives":recall,"recall_on_all_gold_positives":all_recall,
        "f1_on_decided":divide(2*tp,2*tp+fp+fn),"f1_with_all_positive_recall":divide(2*tp,len(positives)+tp+fp),
        "accuracy_on_decided":divide(tp+tn,decided),"correct_fraction_of_all_binary_gold":divide(tp+tn,len(scored)),
        "false_positive_rate_on_decided_negatives":divide(fp,fp+tn),
        "unresolved_gold_positive":sum(r["outcome"] in {"model_unknown","request_error","not_attempted"} for r in positives),
        "unresolved_gold_negative":sum(r["outcome"] in {"model_unknown","request_error","not_attempted"} for r in negatives),
        "excluded_gold_unknown_predictions":dict(Counter(str(r["predicted_entrypoint"]) if r["prediction_status"]=="success" else r["prediction_status"]
                                                            for r in details if r["outcome"]=="excluded_gold_unknown"))}
    tp_items=[(gold[r["case_id"]],predictions[r["case_id"]]) for r in details if r["outcome"]=="tp"]
    all_items=[(gold[r["case_id"]],predictions.get(r["case_id"],{"status":"not_attempted"})) for r in scored]
    exact=sum(r["formation_exact"] for r in positives)
    correct_kinds=sum(r["kind_correct"] for r in positives)
    metrics["classification"]={"true_positive_functions":tp,
        "formation_exact_count":exact,"formation_exact_on_true_positives":divide(exact,tp),
        "formation_exact_on_all_gold_positives":divide(exact,len(positives)),
        "kind_correct_count":correct_kinds,"kind_accuracy_on_true_positives":divide(correct_kinds,tp),
        "kind_correct_on_all_gold_positives":divide(correct_kinds,len(positives)),
        "formation_conditional_on_true_positives":label_metrics(tp_items),
        "formation_end_to_end_on_binary_gold":label_metrics(all_items)}
    def grouped(key):
        groups=defaultdict(list)
        for r in positives:
            keys=gold[r["case_id"]][key] if key=="subtypes" else [gold[r["case_id"]][key]]
            for name in keys:groups[name].append(r)
        return {name:{"gold_positives":len(items),"tp":sum(r["outcome"]=="tp" for r in items),
                      "fn":sum(r["outcome"]=="fn" for r in items),
                      "unresolved":sum(r["outcome"] not in {"tp","fn"} for r in items),
                      "recall":divide(sum(r["outcome"]=="tp" for r in items),len(items))}
                for name,items in sorted(groups.items())}
    metrics["by_primary_kind"]=grouped("entrypoint_kind")
    metrics["by_subtype"]=grouped("subtypes")
    return metrics,details


def write_report(out,metrics,details,provenance):
    out.mkdir(parents=True,exist_ok=True)
    def write(name,data):(out/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    write("metrics.json",metrics)
    write("details.json",details)
    write("manifest.json",provenance)
    columns=("function","file","start_line","outcome","gold_entrypoint","predicted_entrypoint","gold_formations","predicted_formations",
             "extra_formations","missing_formations","unknown_formation_labels","accepted_kinds","predicted_kind","formation_exact","kind_correct",
             "gold_subtypes","gold_reason","evidence_locations","error")
    cohorts={"all-functions.csv":details,"false-positives.csv":[r for r in details if r["outcome"]=="fp"],
             "false-negatives.csv":[r for r in details if r["outcome"]=="fn"],
             "unresolved.csv":[r for r in details if r["outcome"] in {"model_unknown","request_error","not_attempted"}],
             "excluded-gold-unknown.csv":[r for r in details if r["outcome"]=="excluded_gold_unknown"],
             "classification-errors.csv":[r for r in details if r["outcome"]=="tp" and (not r["formation_exact"] or not r["kind_correct"])]}
    for name,rows in cohorts.items():
        with (out/name).open("w",encoding="utf-8-sig",newline="") as stream:
            writer=csv.DictWriter(stream,fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({k:";".join(str(x) for x in row[k]) if isinstance(row[k],list) else row[k] for k in columns})
    m=metrics
    dataset=provenance.get("dataset_name","CTFd")
    version=provenance.get("annotation_version","ctfd-application-v1")
    lines=["# Jev 对 {} ground truth 的评估".format(dataset),"",
        "Ground truth：{}。保留原始标注与模型输出，本报告只做离线匹配计分。".format(version),
        "", "按 case_id 精确匹配，并验证函数身份、源码定义、仓库版本、索引和请求哈希；不按函数名模糊匹配。", "",
        "## 评估范围", "", "| 项目 | 数量 |","|---|---:|"]
    for key in ("ground_truth_total","ground_truth_positives","ground_truth_negatives","excluded_gold_unknown","predictions_available",
                "successful_predictions","binary_decisions_scored","model_unknown","request_errors","not_attempted"):
        lines.append("| {} | {} |".format(key,m[key]))
    lines += ["", "## 入口识别", "", "| Ground truth / Jev | 是入口 | 非入口 | 不确定/失败/未执行 |",
              "|---|---:|---:|---:|", "| 是入口 | {} | {} | {} |".format(m["tp"],m["fn"],m["unresolved_gold_positive"]),
              "| 非入口 | {} | {} | {} |".format(m["fp"],m["tn"],m["unresolved_gold_negative"]), "",
              "| 指标 | 数值 | 分母说明 |","|---|---:|---|",
              "| 精确率 | {} | TP/(TP+FP)，排除 ground truth unknown |".format(percentage(m["precision"])),
              "| 全正例召回率 | {} | TP/全部 {} 个确定正例，不确定/失败/未执行没有被算作已找到 |".format(percentage(m["recall_on_all_gold_positives"]),m["ground_truth_positives"]),
              "| F1（全正例召回口径） | {} | 上述精确率与全正例召回率的调和平均 |".format(percentage(m["f1_with_all_positive_recall"])),
              "| 确定回答召回率 | {} | TP/(TP+FN)，仅统计模型明确 yes/no 的正例 |".format(percentage(m["recall_on_decided_positives"])),
              "| 确定回答 F1 | {} | 与确定回答召回率对应 |".format(percentage(m["f1_on_decided"])),
              "| 确定回答准确率 | {} | (TP+TN)/{} |".format(percentage(m["accuracy_on_decided"]),m["binary_decisions_scored"]),
              "| 全部确定真值的正确比例 | {} | (TP+TN)/{}，保留模型未决造成的缺口 |".format(percentage(m["correct_fraction_of_all_binary_gold"]),m["ground_truth_positives"]+m["ground_truth_negatives"]),
              "| 负例误报率 | {} | FP/(FP+TN) |".format(percentage(m["false_positive_rate_on_decided_negatives"])), "",
              "FN 只表示模型明确回答 no 的真实入口；模型 unknown、请求失败和缺失分别保留，不伪装为 FN 或 TN。",
              "ground truth 的 unknown 条目不进入二元识别和分类评分。", "",
              "## 按标注主用途的入口召回", "", "| 用途 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |", "|---|---:|---:|---:|---:|---:|"]
    for name,group in m["by_primary_kind"].items():
        lines.append("| {} | {} | {} | {} | {} | {} |".format(name,group["gold_positives"],group["tp"],group["fn"],group["unresolved"],percentage(group["recall"])))
    if m.get("by_scope_partition"):
        lines += ["", "## 分范围统计", "", "| 范围 | 函数 | TP | FP | FN | TN | GT 不确定 | 请求失败 | 精确率 | 全正例召回率 | F1 |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for name,v in m["by_scope_partition"].items():
            lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(name,
                v["ground_truth_total"],v["tp"],v["fp"],v["fn"],v["tn"],v["excluded_gold_unknown"],v["request_errors"],
                percentage(v["precision"]),percentage(v["recall_on_all_gold_positives"]),percentage(v["f1_with_all_positive_recall"])))
    c=m["classification"]
    lines += ["", "## 已正确识别入口后的分类", "", "仅在 {} 个 TP 上评价分类，避免把识别漏报与分类错误混在一起。".format(m["tp"]), "",
              "- 形成方式完全匹配：{}/{}（{}）。".format(c["formation_exact_count"],m["tp"],percentage(c["formation_exact_on_true_positives"])),
              "- 用途匹配：{}/{}（{}）；命中 entrypoint_kinds 任一合法用途即可。".format(c["kind_correct_count"],m["tp"],percentage(c["kind_accuracy_on_true_positives"])),
              "- 形成方式 micro P/R/F1：{} / {} / {}。".format(*[percentage(c["formation_conditional_on_true_positives"][k]) for k in ("micro_precision","micro_recall","micro_f1")]), "",
              "| 形成方式 | 真值支持数 | TP | FP（多选） | FN（未命中） | unknown | 精确率 | 召回率 | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for label,v in c["formation_conditional_on_true_positives"]["per_label"].items():
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(label,v["support"],v["tp"],v["fp"],v["fn"],v["unknown"],percentage(v["precision"]),percentage(v["recall"]),percentage(v["f1"])))
    lines += ["", "形成方式 exact match 要求全部标签一致，任一分类问题 unknown 不计完全正确。micro 指标按实际输出 yes 的标签评分，未决标签另列。",
              "端到端形成方式 micro 指标另见 metrics.json：未找到的正例标签作为未恢复标签，负例上预测出的标签作为额外标签。", "",
              "## 按入口子类型定位漏报", "", "子类型允许重叠，下面各行不能直接相加当作函数总数。", "",
              "| 子类型 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |", "|---|---:|---:|---:|---:|---:|"]
    for name,v in m["by_subtype"].items():
        lines.append("| {} | {} | {} | {} | {} | {} |".format(name,v["gold_positives"],v["tp"],v["fn"],v["unresolved"],percentage(v["recall"])))
    lines += ["", "## 逐条结果", "", "误报见 false-positives.csv，明确漏报见 false-negatives.csv；unresolved.csv 与 excluded-gold-unknown.csv 分开保存。",
              "分类错误见 classification-errors.csv；全量配对、真值理由与证据位置见 all-functions.csv / details.json。", "",
              "## 实验解释", "", "本次按用户指定的静态参考集作为 ground truth。其来源、边界和 {} 个不确定项保留在原始数据集中。".format(m["excluded_gold_unknown"]),
              "评测没有修改标注、阈值筛选预测、人工纠正回答或重新调用模型；结果仅针对该固定仓库和标注口径。"]
    (out/"REPORT.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("Ground truth scored        : {} (excluded unknown: {})".format(len(details)-m["excluded_gold_unknown"],m["excluded_gold_unknown"]))
    print("TP / FP / FN / TN          : {} / {} / {} / {}".format(m["tp"],m["fp"],m["fn"],m["tn"]))
    print("Model unknown / errors     : {} / {}".format(m["model_unknown"],m["request_errors"]))
    print("Precision                  : "+percentage(m["precision"]))
    print("Recall (all positives)     : "+percentage(m["recall_on_all_gold_positives"]))
    print("F1 (all-positive recall)   : "+percentage(m["f1_with_all_positive_recall"]))
    print("Formation exact (TP only)  : "+percentage(c["formation_exact_on_true_positives"]))
    print("Kind accuracy (TP only)    : "+percentage(c["kind_accuracy_on_true_positives"]))
    print("Report                     : "+str(out/"REPORT.md"))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold",type=Path,default=HERE/"annotations/ctfd-application-v1")
    parser.add_argument("--run",type=Path,default=HERE/"runs/jev-ctfd-application-bindings-v3")
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    if (args.out/"manifest.json").exists():raise ValueError("Choose a fresh --out to preserve the prior evaluation")
    gold_bytes=(args.gold/"annotations.json").read_bytes()
    prediction_bytes=(args.run/"results.json").read_bytes()
    prepared_bytes=(args.run/"prepared.json").read_bytes()
    gold=json.loads(gold_bytes)
    predictions=json.loads(prediction_bytes)
    prepared=json.loads(prepared_bytes)
    gm=json.loads((args.gold/"manifest.json").read_text())
    pm=json.loads((args.run/"manifest.json").read_text())
    if gm["repository_commit"]!=pm["repository_commit"] or gm["index_hashes"]!=pm["index_hashes"]:
        raise ValueError("Ground truth and predictions use different repository/index versions")
    prepared_by_id={r["case_id"]:r for r in prepared}
    if len(prepared_by_id)!=len(prepared):raise ValueError("Duplicate prepared case IDs")
    for g in gold:
        p=prepared_by_id.get(g["case_id"])
        if p is None or p["function_id"]!=g["function_id"] or p["definition_identity"]!=g["definition_identity"]:
            raise ValueError("Ground truth/prepared definition identity mismatch")
    for p in predictions:
        expected=prepared_by_id.get(p["case_id"])
        if expected is None or p["request_hash"]!=expected["request_hash"]:
            raise ValueError("Prediction request hash mismatch")
    verification=json.loads((args.gold/"verification.json").read_text())
    gold_digest=hashlib.sha256(gold_bytes).hexdigest()
    if gold_digest!=verified_annotation_digest(verification):
        raise ValueError("Ground truth changed since verification")
    if gm.get("annotations_sha256",gold_digest)!=gold_digest:
        raise ValueError("Ground-truth manifest hash mismatch")
    if hashlib.sha256((args.gold/"POLICY.md").read_bytes()).hexdigest()!=gm["policy_sha256"]:
        raise ValueError("Ground-truth policy changed since annotation")
    metrics,details=analyze(gold,predictions)
    partitions=sorted({g["scope_partition"] for g in gold if g.get("scope_partition")})
    if partitions:
        metrics["by_scope_partition"]={}
        for name in partitions:
            cohort=[g for g in gold if g.get("scope_partition")==name]
            ids={g["case_id"] for g in cohort}
            metrics["by_scope_partition"][name]=analyze(cohort,[p for p in predictions if p["case_id"] in ids])[0]
    provenance={"created_at":datetime.now(timezone.utc).isoformat(),"repository_commit":gm["repository_commit"],
        "dataset_name":Path(gm["repository"]).name if gm.get("repository") else args.gold.name,
        "annotation_version":gm.get("annotation_version",args.gold.name),
        "model_alias":pm["model"],"resolved_models":sorted({s["input_audit"]["resolved_model"] for p in predictions for s in p.get("stages",[]) if s.get("input_audit",{}).get("resolved_model")}),
        "ground_truth":str(args.gold.resolve()),"prediction_run":str(args.run.resolve()),
        "ground_truth_sha256":gold_digest,"predictions_sha256":hashlib.sha256(prediction_bytes).hexdigest(),
        "prepared_sha256":hashlib.sha256(prepared_bytes).hexdigest(),
        "evaluator_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "ground_truth_use":"user_accepted_for_current_experiment","api_called":False,
        "unknown_gold_policy":"exclude from scored binary/classification cohorts; retain separate rows",
        "model_unresolved_policy":"not silently changed to no; counted separately and not recovered in all-positive recall"}
    write_report(args.out,metrics,details,provenance)
    (args.out/"ground-truth.snapshot.json").write_bytes(gold_bytes)
    (args.out/"predictions.snapshot.json").write_bytes(prediction_bytes)
    (args.out/"ground-truth-policy.snapshot.md").write_bytes((args.gold/"POLICY.md").read_bytes())


if __name__=="__main__":
    main()
