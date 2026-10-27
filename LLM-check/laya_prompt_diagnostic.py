#!/usr/bin/env python3
"""Controlled wording/context checks on the existing notifications example."""

import argparse
import copy
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "runs/laya-prompt-diagnostic-v1"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare():
    baseline = json.loads((HERE / "runs/laya-four-v1/requests/case_01.json").read_text())
    context = json.loads((HERE / "runs/laya-four-v1/contexts/case_01.json").read_text())
    instruction = "Is the target function notifications itself an instance method of a class inheriting a framework handler base? Judge notifications, not the application object CTFdFlask."
    criteria = {
        "yes": "notifications is a method defined inside a framework handler subclass.",
        "no": "notifications is a module-level function, not a method of a subclass.",
        "unknown": "The function's enclosing scope is not shown."
    }
    questions = {
        "inheritance_original_zh": copy.deepcopy(baseline["questions"]["formation_inheritance"]),
        "inheritance_specific_zh": {
            "type": "choice",
            "instructions": "目标 notifications 自身是否是继承框架处理基类的类方法？判断 notifications，不是应用对象 CTFdFlask。",
            "criteria": {"yes": "notifications 定义在框架处理子类内部，是该类的方法。",
                         "no": "notifications 是模块顶层函数，不是子类方法。",
                         "unknown": "没有显示函数所属作用域。"}
        },
        "inheritance_specific_en": {"type": "choice", "instructions": instruction, "criteria": criteria},
        "inheritance_neutral_keys_en": {
            "type": "choice", "instructions": instruction,
            "criteria": {"A": criteria["yes"], "B": criteria["no"], "C": criteria["unknown"]}
        },
        "inheritance_reordered_en": {
            "type": "choice", "instructions": instruction,
            "criteria": {"unknown": criteria["unknown"], "no": criteria["no"], "yes": criteria["yes"]}
        },
        "inheritance_boolean_en": {
            "type": "noul",
            "instructions": "The function notifications is defined inside a framework handler subclass as one of its methods."
        },
        "decorator_specific_en": {
            "type": "choice", "instructions": "Does notifications have a route-registration decorator?",
            "criteria": {"A": "Yes: a route decorator binds notifications as a request handler.",
                         "B": "No: notifications has no route-registration decorator.",
                         "C": "Unknown: the function's decorators are not shown."}
        },
        "entrypoint_specific_en": {
            "type": "choice", "instructions": "Is notifications registered to handle HTTP requests?",
            "criteria": {"A": "Yes: it is bound as an HTTP handler by a route decorator or registration call.",
                         "B": "No: it is only an internal utility with no request-handler binding.",
                         "C": "Unknown: no registration or routing information is shown."}
        },
        "primary_mechanism_en": {
            "type": "choice", "instructions": "Which mechanism directly binds the target function notifications as a handler? Choose the mechanism for notifications itself.",
            "criteria": {
                "decorator": "A route-registration decorator applied to the function.",
                "registration": "An explicit call passing the function as a handler argument.",
                "inheritance": "A method overriding a framework handler base class.",
                "interface": "An explicit interface or abstract handler contract implementation.",
                "configuration": "A configuration file binds this function by name.",
                "callback": "A framework lifecycle hook or external event callback.",
                "none": "No entrypoint binding is shown.",
                "unknown": "Cannot identify the mechanism."
            }
        }
    }
    minimal = "Target function: notifications. Source file: CTFd/views.py.\n" + context["target"]["source"]
    variants = {"same_full_context": baseline["state"], "target_source_only": minimal}
    # Question semantics remain the same across contexts; prior results are preserved.
    for name, state in variants.items():
        payload = {"model": "multilingual", "state": state, "questions": questions,
                   "max_len": 8192, "head_max_len": 512}
        save(OUT / "requests" / (name + ".json"), payload)
    expected = {qid: "no" for qid in questions if qid.startswith("inheritance_")}
    expected.update(inheritance_neutral_keys_en="B", inheritance_boolean_en="P(true) low",
                    decorator_specific_en="A", entrypoint_specific_en="A", primary_mechanism_en="decorator")
    save(OUT / "design.json", {
        "variant_dimensions": ["question wording/language/answer keys", "full context versus target source only"],
        "expected_for_review_only": expected,
        "limits": "One known function, diagnostic contrasts only; not a classification accuracy benchmark.",
        "baseline_response": str(HERE / "runs/laya-four-v1/responses/case_01.json")})


def summarize():
    expected = json.loads((OUT / "design.json").read_text())["expected_for_review_only"]
    lines = ["# Laya 提问方式与上下文对照", "", "同一个 notifications 函数；原始四例实验没有覆盖。",
             "人工预期仅用于下表复核，不放入请求元数据中。单个问题中的候选项是通常的假设陈述。", "",
             "| 问题 | 人工预期 | 原上下文 | 仅目标源码 |", "|---|---|---|---|"]
    responses = {name: json.loads((OUT / "responses" / (name + ".json")).read_text())
                 for name in ("same_full_context", "target_source_only")}
    for name, response in responses.items():
        if response.get("usage", {}).get("truncated"):
            raise ValueError("Server truncated " + name)
    for qid, exp in expected.items():
        values = []
        for response in responses.values():
            answer = response["answers"][qid]
            if answer["type"] == "noul":
                values.append("P(true)={:.4f}".format(answer["noul"]))
            else:
                values.append("{} ({})".format(answer["choice"], json.dumps(answer["probabilities"], ensure_ascii=False)))
        lines.append("| {} | {} | {} | {} |".format(qid, exp, *values))
    lines += ["", "原始请求和回复分别保存在 requests/、responses/。",
              "这两组请求可显示敏感性，不能单独确定所有错误的原因或模型整体能力。", ""]
    (OUT / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "summarize"))
    args = parser.parse_args()
    prepare() if args.command == "prepare" else summarize()
