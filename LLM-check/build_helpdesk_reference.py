#!/usr/bin/env python3
"""Source-only django-helpdesk reference annotations; never reads model output.

Reuses the CTFd evidence/identity machinery, but not its Flask recognition rules.
The reviewed Django contracts and scope are frozen in annotations/*/POLICY.md.
"""

import argparse
import ast
import csv
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from build_ctfd_reference import ReferenceReview, FORMATIONS, KINDS
from context_graph import ContextGraph

HERE = Path(__file__).resolve().parent
PREFIX = "src/helpdesk/"
URLS = PREFIX + "urls.py"
EXPECTED_COMMIT = "8c7b9ff92f018a394c6faa972e4328ad178b80b9"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "dispatch"}
CBV_HOOKS = HTTP_METHODS | {
    "get_context_data", "get_initial", "get_form_kwargs", "get_form_class", "get_form",
    "form_valid", "form_invalid", "get_success_url", "get_object", "get_queryset",
    "get_serializer", "perform_create", "test_func",
}
FEED_HOOKS = {"get_object", "title", "description", "link", "items", "item_pubdate", "item_author_name"}


class HelpdeskReview(ReferenceReview):
    def __init__(self, graph):
        super().__init__(graph)
        self.dispatch_inventory = []

    def resolve(self, node, file):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            return []
        ids, _, _ = self.graph.resolve(ast.unparse(node), file, None, node.lineno)
        return [self.graph.nodes[i] for i in ids
                if self.graph.nodes[i].get("record_type") in {"functions", "classes"}]

    def find(self, file, needle, role="dispatch"):
        # Documentation is evidence text, never Python source to parse.
        if file.endswith(".py"):
            return super().find(file, needle, role)
        if file not in self.lines:
            self.lines[file] = (self.graph.repo / file).read_text(encoding="utf-8").splitlines(keepends=True)
        matches = [i for i, line in enumerate(self.lines[file], 1) if needle in line]
        if not matches:
            raise ValueError("Missing evidence: " + file + " " + needle)
        return self.evidence(file, matches[0], role=role)

    def ev_node(self, file, node, role="binding"):
        return self.evidence(file, node.lineno, node.end_lineno, role)

    def ancestors(self, cls):
        """Local inheritance evidence only; external contracts are reviewed below."""
        pending, seen = [cls], set()
        while pending:
            row = pending.pop(0)
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            yield row
            for edge in self.graph.outgoing[row["id"]]:
                if edge["relation"] == "inherits":
                    parent = self.graph.nodes[edge["target"]]
                    if parent.get("record_type") == "classes":
                        pending.append(parent)

    def bind_class(self, cls, file, site, source_type, feed=False):
        evidence = [self.ev_node(file, site, "receiver_binding")]
        allowed = FEED_HOOKS if feed else CBV_HOOKS
        emitted = []
        for owner in self.ancestors(cls):
            for row in self.functions:
                if row.get("scope_id") != owner["id"] or row["name"] not in allowed:
                    continue
                # In this snapshot every shadowed included base hook is also
                # used through super() by a bound subclass. Regression checks
                # pin those paths; this is not a general Python MRO resolver.
                types = ["registration", "inheritance"]
                if feed or row["name"] not in HTTP_METHODS:
                    types.append("callback")
                self.mark(row, True, types, "http", "django_feed_hook" if feed else source_type,
                          "承载类 {} 已绑定；目标是该具体类或其基类中实际使用的框架调度方法，而非仅凭方法名/继承判正。".format(cls["qualified_name"]),
                          evidence, "安装 helpdesk，并启用该 URL/API 配置或对应视图分支时")
                emitted.append(row["id"])
        return sorted(set(emitted))

    def automatic_evidence(self):
        # Every URL callable and router receiver is inventoried, including
        # external Django auth/TemplateView targets that have no local def.
        tree = self.syntax(URLS)
        for call in sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)), key=lambda n: n.lineno):
            name = ast.unparse(call.func)
            if name not in {"path", "re_path", "router.register"} or len(call.args) < 2:
                continue
            expr, bound = call.args[1], []
            if name == "router.register":
                for cls in self.resolve(expr, URLS):
                    if cls["record_type"] == "classes":
                        bound += self.bind_class(cls, URLS, call, "drf_viewset_hook")
            else:
                for target in self.resolve(expr, URLS):
                    if target["record_type"] == "functions" and target.get("origin") == "source_definition":
                        self.mark(target, True, ["registration"], "http", "django_url_function",
                                  "URLconf 的 path/re_path 直接绑定此逻辑视图；鉴权/缓存装饰器不是额外的入口形成标签。",
                                  [self.ev_node(URLS, call, "url_binding")], "安装 helpdesk 并 include(helpdesk.urls)，且相应功能开关启用时")
                        bound.append(target["id"])
                for node in ast.walk(expr):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
                            for cls in self.resolve(node.func.value, URLS):
                                if cls["record_type"] == "classes":
                                    bound += self.bind_class(cls, URLS, call, "django_class_view_hook")
                        for cls in self.resolve(node.func, URLS):
                            if cls["record_type"] == "classes" and cls["file"] == PREFIX + "views/feeds.py":
                                bound += self.bind_class(cls, URLS, call, "django_feed_hook", feed=True)
            expression = ast.unparse(expr)
            resolution = "local_source_definitions" if bound else (
                "external_inherited_actions" if expression == "CreateUserView" else
                "included_router" if expression == "include(router.urls)" else
                "external_framework_callable" if expression in {"logout", "password_change", "password_change_done", "password_reset", "password_reset_done", "password_reset_confirm", "password_reset_complete"}
                or expression.startswith("TemplateView.as_view(") else "unresolved")
            conditions = []
            parent = self.parents[URLS].get(call)
            while parent:
                if isinstance(parent, ast.If):
                    conditions.append(ast.unparse(parent.test))
                parent = self.parents[URLS].get(parent)
            self.dispatch_inventory.append({"file": URLS, "start_line": call.lineno,
                "expression": expression, "registration": name, "target_function_ids": sorted(set(bound)),
                "resolution": resolution, "enclosing_conditions": list(reversed(conditions))})
            if resolution == "unresolved":
                raise ValueError("Unreviewed URL binding: " + expression)

        # as_view() in both URLconf and explicit request delegation inside views.
        for file in sorted({r["file"] for r in self.functions}):
            if file == URLS:
                continue  # Full path()/re_path() evidence already attached above.
            for call in ast.walk(self.syntax(file)):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute) or call.func.attr != "as_view":
                    continue
                for cls in self.resolve(call.func.value, file):
                    if cls["record_type"] != "classes":
                        continue
                    bound = self.bind_class(cls, file, call, "django_class_view_hook")
                    self.dispatch_inventory.append({"file": file, "start_line": call.lineno,
                        "expression": ast.unparse(call), "registration": "as_view", "receiver": cls["qualified_name"],
                        "target_function_ids": bound})

        for row in self.functions:
            node = self.definition(row)
            for decorator in node.decorator_list:
                text = ast.unparse(decorator)
                if row["file"].startswith(PREFIX + "templatetags/") and text.startswith("register."):
                    self.mark(row, True, ["callback", "decorator"], "other", "django_template_registration",
                              "Django Library 装饰器将此函数绑定为模板过滤器/标签；普通模板内部辅助函数不按此规则扩张。",
                              [self.ev_node(row["file"], decorator, "template_binding")], "模板加载该 Library 并调用标签/过滤器时")
                elif row["file"] == PREFIX + "webhooks.py" and text.startswith("receiver("):
                    self.mark(row, True, ["callback", "decorator"], "event", "django_signal_receiver",
                              "receiver 装饰器注册信号处理函数，AppConfig.ready 导入该模块完成注册。",
                              [self.ev_node(row["file"], decorator, "signal_binding"), self.find(PREFIX + "apps.py", "from . import webhooks")])
                elif row["file"] == PREFIX + "tasks.py" and text == "shared_task":
                    self.mark(row, True, ["decorator"], "event", "celery_shared_task",
                              "shared_task 将函数注册为 Celery 消息任务；配置文档给出了按任务全名设置周期任务的方式。",
                              [self.ev_node(row["file"], decorator, "task_binding"), self.find(URLS, "import helpdesk.tasks"),
                               self.find("docs/configuration.rst", "helpdesk.tasks.helpdesk_process_email")], "安装 Celery 可选依赖并启用 worker/调度时")

        # Explicit Library.filter(function) registrations and migration callbacks.
        for file in sorted({r["file"] for r in self.functions}):
            for call in ast.walk(self.syntax(file)):
                if not isinstance(call, ast.Call):
                    continue
                name = ast.unparse(call.func)
                args, subtype, kind, reason = [], None, None, None
                if "/templatetags/" in file and name == "register.filter":
                    args = call.args
                    subtype, kind = "django_template_registration", "other"
                    reason = "Library.filter 显式注册目标函数，可由模板系统回调。"
                elif "/migrations/" in file and name == "migrations.RunPython":
                    args = list(call.args[:2]) + [k.value for k in call.keywords if k.arg in {"code", "reverse_code"}]
                    subtype, kind = "django_data_migration", "lifecycle"
                    reason = "函数作为 RunPython 的正向/反向执行回调绑定；迁移辅助函数和迁移执行回调分别标注。"
                elif file == PREFIX + "models.py" and name == "models.signals.post_save.connect":
                    args = call.args[:1]
                    subtype, kind = "django_signal_receiver", "event"
                    reason = "post_save.connect 显式注册用户保存后的处理函数。"
                for arg in args:
                    for target in self.resolve(arg, file):
                        if target["record_type"] == "functions" and target["id"] in {f["id"] for f in self.functions}:
                            self.mark(target, True, ["registration", "callback"], kind, subtype, reason,
                                      [self.ev_node(file, call, "callback_registration")],
                                      "模板/信号触发，或执行该迁移的正向/反向过程时")

        # Callable field configuration, including frozen historical migrations.
        for file_row in self.graph.tables["files"]:
            file = file_row["file"]
            if file_row["area"] != "application":
                continue
            for call in ast.walk(self.syntax(file)):
                if not isinstance(call, ast.Call) or not ast.unparse(call.func).endswith("Field"):
                    continue
                for kw in call.keywords:
                    if kw.arg not in {"default", "upload_to", "validators"}:
                        continue
                    values = kw.value.elts if isinstance(kw.value, (ast.List, ast.Tuple)) else [kw.value]
                    for value in values:
                        for target in self.resolve(value, file):
                            if target["record_type"] == "functions" and target.get("area") == "application":
                                self.mark(target, True, ["configuration", "callback"],
                                          "lifecycle" if "/migrations/" in file else "other",
                                          "django_field_" + kw.arg,
                                          "字段 {} 配置保存可调用对象，Django 在构造默认值、上传路径或校验阶段调用它；立即调用得到的值不按此规则判正。".format(kw.arg),
                                          [self.ev_node(file, call, "field_callable_configuration")])

    def explicit_reviews(self):
        p = PREFIX
        label = self.label
        label(p + "apps.py", "HelpdeskConfig.ready", True, ["inheritance", "callback"], "lifecycle", "django_app_ready",
              "AppConfig.ready 是 Django 应用注册完成后的启动钩子；文档要求将 helpdesk 安装到 INSTALLED_APPS。",
              [(p + "apps.py", 'name = "helpdesk"'), ("docs/install.rst", "'helpdesk',  # This is us!")])

        for row in self.functions:
            if row["file"].startswith(p + "management/commands/") and row["lexical_name"] in {"Command.handle", "Command.add_arguments"}:
                self.mark(row, True, ["inheritance", "callback"], "cli", "django_management_command",
                          "已安装 app 的 management/commands 模块由 Django 发现；BaseCommand 调度该 handle/add_arguments 覆盖方法。",
                          [self.find(row["file"], "class Command(BaseCommand):"), self.find("docs/install.rst", "'helpdesk',  # This is us!")],
                          "执行对应 manage.py 子命令（add_arguments 在参数解析阶段）时")

        # The five custom ModelAdmin methods all have concrete admin receivers.
        for owner, method in (
            ("QueueAdmin", "time_spent"),
            ("TicketAdmin", "time_spent"),
            ("TicketAdmin", "hidden_submitter_email"),
            ("FollowUpAdmin", "ticket_get_ticket_for_url"),
        ):
            row = self.by_name[(p + "admin.py", owner + "." + method)][0]
            cls = self.graph.nodes[row["scope_id"]]
            tree = self.syntax(row["file"])
            definition = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.lineno == cls["start_line"])
            mapping = next(n for n in definition.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                           and any(isinstance(t, ast.Name) and t.id == "list_display" for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
            registration = definition.decorator_list[0]
            self.mark(row, True, ["configuration", "callback", "decorator"], "other", "django_admin_display",
                      "已注册的 ModelAdmin.list_display 按名称选择此方法作为后台列表显示回调；admin.display 仅提供显示元数据。",
                      [self.ev_node(row["file"], mapping, "admin_column_configuration"), self.ev_node(row["file"], registration, "admin_receiver_registration")])
        label(p + "admin.py", "QueueAdmin.delete_queryset", True, ["inheritance", "callback", "decorator"], "other", "django_admin_delete_hook",
              "QueueAdmin 经 admin.register 绑定，后台批量删除调用其 delete_queryset 覆盖钩子。", [(p + "admin.py", "@admin.register(Queue)")])

        label(p + "models.py", "EscapeHtml.extendMarkdown", True, ["inheritance", "configuration", "callback"], "other", "markdown_extension_hook",
              "EscapeHtml 实例被装入 markdown.extensions；Markdown 通过 Extension 扩展契约调用 extendMarkdown。", [(p + "models.py", "EscapeHtml(),")])
        label(p + "models.py", "CustomFieldManager.get_queryset", True, ["inheritance", "configuration", "callback"], "other", "django_manager_hook",
              "CustomField.objects 配置为 CustomFieldManager，ORM 的管理器查询调用 get_queryset 覆盖方法。", [(p + "models.py", "objects = CustomFieldManager()")])
        for name in ("FollowUpAttachment", "KBIAttachment"):
            label(p + "models.py", name + ".attachment_path", True,
                  ["inheritance", "interface_implementation", "callback"], "other", "attachment_path_implementation",
                  "具体附件模型实现 Attachment 明确声明的 attachment_path 契约；FileField.upload_to 绑定的桥接函数按实例调度此实现。",
                  [(p + "models.py", "upload_to=attachment_path"), (p + "models.py", "return instance.attachment_path(filename)"),
                   (p + "models.py", "This method is to be implemented by Attachment classes")])

        # ORM/admin/ModelForm hooks on actually installed concrete model types.
        for owner in ("Queue", "Ticket", "FollowUp", "Attachment", "KBItem", "IgnoreEmail"):
            refs = [("docs/install.rst", "'helpdesk',  # This is us!")]
            if owner == "Attachment":
                refs += [(p + "models.py", "class FollowUpAttachment(Attachment):"), (p + "models.py", "class KBIAttachment(Attachment):")]
            else:
                refs += [(p + "models.py", "class " + owner + "(models.Model):")]
            label(p + "models.py", owner + ".save", True, ["inheritance", "callback"], "other", "django_model_save_hook",
                  "已安装模型的 Model.save 覆盖方法；ORM/ModelForm/Admin 的持久化流程可调用该方法。抽象 Attachment.save 由具体附件模型继承。", refs)
        label(p + "models.py", "Queue.delete", True, ["inheritance", "callback"], "other", "django_model_delete_hook",
              "已注册 Queue 后台的单对象删除使用 Model.delete 覆盖契约；批量删除还通过 QueueAdmin.delete_queryset 显式调用它。",
              [(p + "admin.py", "@admin.register(Queue)"), (p + "admin.py", "queue.delete()")])
        for owner in ("Ticket", "FollowUp", "KBCategory", "KBItem"):
            label(p + "models.py", owner + ".get_absolute_url", True, ["callback"], "other", "django_model_absolute_url",
                  "模型已注册 Django Admin，后台 view-on-site 通过 get_absolute_url 命名契约取得对象 URL；不是任意 get_* 辅助方法。",
                  [(p + "admin.py", "@admin.register(" + owner + ")")], "对应模型后台启用且对象存在时（知识库受 KB 开关控制）")
        label(p + "models.py", "TicketCC.clean", True, ["inheritance", "callback"], "other", "django_model_clean_hook",
              "TicketCC 被 ModelForm.Meta.model 选择，ModelForm._post_clean 调用模型 full_clean/clean 钩子。",
              [(p + "forms.py", "model = TicketCC")])

        label(p + "email.py", "process_email", True, ["other"], "cli", "python_module_main",
              "get_email 命令模块的 __main__ 分支直接选择 process_email 作为模块脚本主逻辑；它被其他任务/命令普通调用不是额外形成机制。",
              [(p + "management/commands/get_email.py", 'if __name__ == "__main__":'),
               (p + "management/commands/get_email.py", "    process_email()")],
              "按模块脚本执行 get_email，且宿主已配置 Django 环境/应用初始化时；常规入口仍是 Command.handle")

        # SerializerMethodField binds get_<field>; other get_* helpers do not.
        file = p + "serializers.py"
        tree = self.syntax(file)
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            for stmt in cls.body:
                if not isinstance(stmt, ast.Assign) or not isinstance(stmt.value, ast.Call) or ast.unparse(stmt.value.func) != "serializers.SerializerMethodField":
                    continue
                field = stmt.targets[0].id
                target = self.by_name[(file, cls.name + ".get_" + field)]
                if len(target) != 1:
                    raise ValueError("Missing SerializerMethodField target: " + field)
                self.mark(target[0], True, ["inheritance", "configuration", "callback"], "other", "drf_serializer_method_field",
                          "SerializerMethodField 的命名契约绑定 get_<字段> 方法，由 DRF 序列化流程回调。",
                          [self.ev_node(file, stmt, "serializer_field_binding"), self.find(p + ("query.py" if cls.name == "DatatablesTicketSerializer" else "views/api.py"),
                           "DatatablesTicketSerializer(" if cls.name == "DatatablesTicketSerializer" else "serializer_class = PublicTicketListingSerializer")])
        for cls, methods in (("FollowUpSerializer", ("create",)), ("UserSerializer", ("validate", "create")), ("TicketSerializer", ("create", "update"))):
            for method in methods:
                label(file, cls + "." + method, True, ["inheritance", "configuration", "callback"], "other", "drf_serializer_hook",
                      "已绑定 viewset 的 serializer_class 实现 DRF 保存/校验钩子，由框架验证或 serializer.save 调度。",
                      [(p + "views/api.py", "serializer_class = " + cls)])
        for cls, method, use in (("EditFollowUpForm", "clean", "form = EditFollowUpForm("),
                                 ("MultipleTicketSelectForm", "clean_tickets", "MultipleTicketSelectForm("),
                                 ("ChecklistTemplateForm", "clean_task_list", "ChecklistTemplateForm(")):
            label(p + "forms.py", cls + "." + method, True, ["inheritance", "callback"], "other", "django_form_clean_hook",
                  "业务视图实际实例化此表单，Django full_clean 按 clean/clean_<字段> 契约调用该方法。",
                  [(p + "views/staff.py", use)])

        for name, config, consumer in (
            ("get_followup_webhook_urls", 'settings, "HELPDESK_GET_FOLLOWUP_WEBHOOK_URLS", get_followup_webhook_urls', (p + "webhooks.py", "settings.HELPDESK_GET_FOLLOWUP_WEBHOOK_URLS()")),
            ("get_new_ticket_webhook_urls", 'settings, "HELPDESK_GET_NEW_TICKET_WEBHOOK_URLS", get_new_ticket_webhook_urls', (p + "webhooks.py", "settings.HELPDESK_GET_NEW_TICKET_WEBHOOK_URLS()")),
            ("HELPDESK_KBITEM_TEAM_GETTER", "def HELPDESK_KBITEM_TEAM_GETTER(_kbitem):", (p + "models.py", "helpdesk_settings.HELPDESK_KBITEM_TEAM_GETTER(self)")),
        ):
            label(p + "settings.py", name, True, ["configuration", "callback"], "other", "configured_settings_callback",
                  "函数占据命名的可替换配置回调槽，消费端通过该槽调用；默认实现和外部自定义实现由设置选择。",
                  [(p + "settings.py", config), consumer], "使用该配置默认实现/禁用 teams 的对应分支时")
        label(p + "decorators.py", "check_staff_status.check_superuser_status.check_user_status", True,
              ["registration", "callback"], "other", "django_authorization_predicate",
              "工厂返回的最终用户谓词被交给 Django user_passes_test；它是权限回调，外层工厂和共享 wrapper 不是独立逻辑入口。",
              [(p + "decorators.py", "helpdesk_staff_member_required = user_passes_test(is_helpdesk_staff)"),
               (p + "decorators.py", "helpdesk_superuser_required = user_passes_test(check_staff_status(False)(True))"),
               (p + "decorators.py", "return check_user_status")])

    def template_namespace_reviews(self):
        pass  # Django Library evidence is extracted above; no Flask globals.

    def boundary_reviews(self):
        # CTFd also kept framework-selected data-object construction boundaries
        # uncertain. Preserve that convention rather than silently changing GT.
        for file, name, refs in (
            ("forms.py", "TicketForm.__init__", [(PREFIX + "views/staff.py", "form_class = TicketForm")]),
            ("forms.py", "PublicTicketForm.__init__", [(PREFIX + "settings.py", '"HELPDESK_PUBLIC_TICKET_FORM_CLASS"')]),
            ("forms.py", "AbstractTicketForm.__init__", [(PREFIX + "forms.py", "class TicketForm(AbstractTicketForm):")]),
            ("serializers.py", "BaseTicketSerializer.__init__", [(PREFIX + "views/api.py", "serializer_class = TicketSerializer")]),
        ):
            self.label(PREFIX + file, name, None, ["inheritance", "configuration", "callback"], None,
                       "configured_component_constructor_boundary",
                       "框架选择的表单/序列化组件构造器或其 super 初始化；按沿用的组件构造边界保留不确定，不将它当成普通负例或独立 HTTP handler。", refs)

    def negative_role(self, row):
        file, name = row["file"], row["lexical_name"]
        if file == PREFIX + "decorators.py":
            return "decorator_plumbing", "装饰器/权限工厂或共享 wrapper；已提交给 Django 的最终谓词另行标注，普通包装不转移入口身份。"
        if "/migrations/" in file:
            return "migration_helper", "迁移回调内部直接调用的数据转换/fixture 辅助函数，目标本身没有被 RunPython 绑定。"
        if name == "Attachment.attachment_path":
            return "unregistered_base_contract", "抽象 Attachment 的路径契约占位实现，实际注册对象是两个具体附件模型，其实现另行标注。"
        if row["name"] == "__init__":
            return "internal_constructor", "项目代码直接实例化的普通对象/表单构造器；框架通过命名配置选择的组件构造器已单列不确定项。"
        if row["name"].startswith("__"):
            return "language_protocol", "普通 Python 对象协议/显示方法，按本参考集边界不将 str 等隐式语言协议扩张为应用调度入口。"
        if any(ast.unparse(d) == "property" or ast.unparse(d).endswith(".setter") for d in self.definition(row).decorator_list):
            return "ordinary_descriptor", "模型/业务对象普通属性描述符；未绑定到独立的应用扩展调度槽。"
        if file == PREFIX + "forms.py":
            return "form_internal_helper", "表单内部拼装或业务显式调用的保存/辅助方法；未按已确认的框架校验/配置调度槽绑定。"
        if file == PREFIX + "models.py":
            return "model_internal_helper", "模型普通查询、格式化或业务辅助方法；标准 ORM/后台/字段回调已单列，不因属于模型而全部判正。"
        if "/templatetags/" in file:
            return "template_internal_helper", "模板标签实现内部辅助函数；Library 实际注册的标签/过滤器是其他目标。"
        if "/views/" in file:
            return "view_internal_helper", "视图内部直接调用的权限、查询、格式化或跳转辅助函数；目标本身不是 URL 绑定对象或已确认的框架调度方法。"
        return "internal_helper", "普通业务服务/工具函数，由视图、命令或任务直接调用；没有确认的独立注册、配置或框架调度绑定。"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_outputs(out, records, graph, inventory):
    def write(name, value):
        (out / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for row in records:
        row["scope_partition"] = "migrations" if "/migrations/" in row["file"] else "runtime_application"
        row["framework_contract_references"] = ["POLICY.md#框架契约"] if row["is_entrypoint"] is True else []
    write("annotations.json", records)
    (out / "annotations.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    columns = ("case_id", "function_id", "function", "file", "start_line", "end_line", "scope_partition", "is_entrypoint",
               "formation_types", "entrypoint_kind", "entrypoint_kinds", "subtypes", "candidate_formation_types", "reason", "evidence_locations", "review_status")
    selections = {"annotations.csv": records, "entrypoints.csv": [r for r in records if r["is_entrypoint"] is True],
                  "non-entrypoints.csv": [r for r in records if r["is_entrypoint"] is False],
                  "uncertain.csv": [r for r in records if r["is_entrypoint"] is None],
                  "runtime-application.csv": [r for r in records if r["scope_partition"] == "runtime_application"],
                  "migrations.csv": [r for r in records if r["scope_partition"] == "migrations"]}
    for name, selected in selections.items():
        with (out / name).open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            for row in selected:
                values = {k: row.get(k, "") for k in columns}
                values["is_entrypoint"] = {True: "true", False: "false", None: "unknown"}[row["is_entrypoint"]]
                for key in ("formation_types", "entrypoint_kinds", "subtypes", "candidate_formation_types"):
                    values[key] = ";".join(row[key])
                values["evidence_locations"] = ";".join(f"{e['file']}:{e['start_line']}-{e['end_line']}" for e in row["evidence"])
                writer.writerow(values)

    def counts(rows):
        return {"functions": len(rows), "entrypoints": sum(r["is_entrypoint"] is True for r in rows),
                "non_entrypoints": sum(r["is_entrypoint"] is False for r in rows), "uncertain": sum(r["is_entrypoint"] is None for r in rows)}
    summary = dict(counts(records), files=len({r["file"] for r in records}),
        files_in_scope=sum(r["area"] == "application" for r in graph.tables["files"]),
        source_lines_in_scope=sum(r["lines"] for r in graph.tables["files"] if r["area"] == "application"),
        formation_counts=dict(Counter(t for r in records for t in r["formation_types"])),
        kind_counts=dict(Counter(r["entrypoint_kind"] for r in records if r["is_entrypoint"] is True)),
        subtype_counts=dict(Counter(t for r in records for t in r["subtypes"])),
        partitions={p: counts([r for r in records if r["scope_partition"] == p]) for p in ("runtime_application", "migrations")},
        independent_human_review=False, model_predictions_read=False, api_called=False)
    write("summary.json", summary)
    write("dispatch_inventory.json", inventory)
    scope = []
    all_functions = graph.select_functions("all")
    for f in graph.tables["files"]:
        scope.append({"file": f["file"], "lines": f["lines"], "sha256": f["sha256"],
                      "in_scope": f["area"] == "application",
                      "partition": "migrations" if f["area"] == "application" and "/migrations/" in f["file"] else
                                   "runtime_application" if f["area"] == "application" else "tests" if f["area"] == "tests" else "demo_deployment_docs_scripts",
                      "functions": sum(r["file"] == f["file"] for r in all_functions)})
    write("scope_inventory.json", scope)
    manifest = {"annotation_version": "django-helpdesk-application-v1", "repository": str(graph.repo),
                "repository_commit": graph.summary["commit"],
                "repository_dirty": bool(subprocess.check_output(["git", "-C", str(graph.repo), "status", "--porcelain"], text=True).strip()),
                "created_at": datetime.now(timezone.utc).isoformat(), "policy_sha256": sha(out / "POLICY.md"),
                "builder_sha256": sha(Path(__file__)), "shared_reference_builder_sha256": sha(HERE / "build_ctfd_reference.py"),
                "index_hashes": graph.index_hashes, "annotations_sha256": sha(out / "annotations.json"),
                "annotation_origin": "agent_static_review_with_source_extractors", "independent_human_review": False,
                "model_predictions_read": False, "api_called": False,
                "scope": {"application_root": "src/helpdesk", "source_root": "src", "includes_migrations": True,
                          "excluded": ["tests", "demodesk", "dockerized", "docs", "root scripts"], "excludes_lambdas_and_parser_generated": True},
                "files_sha256": {p: sha(graph.repo / p) for p in sorted({e["file"] for r in records for e in r["evidence"]})}}
    write("manifest.json", manifest)
    lines = ["# django-helpdesk 逐函数静态参考标注", "", "AI 辅助静态参考，可作为当前实验 ground truth；尚未经独立人工复核。口径见 [POLICY.md](POLICY.md)。", "",
             f"{len(records)} 个定义：入口 {summary['entrypoints']}，非入口 {summary['non_entrypoints']}，不确定 {summary['uncertain']}。", ""]
    for decision, title in ((True, "入口"), (None, "不确定"), (False, "非入口")):
        lines += ["## " + title, "", "| 函数 | 源码 | 形成方式 | 用途 | 判断依据 |", "|---|---|---|---|---|"]
        for r in records:
            if r["is_entrypoint"] is decision:
                reason = r["reason"].replace("|", "\\|").replace("\n", " ")
                lines.append(f"| `{r['function']}` | [{r['file']}:{r['start_line']}]({graph.repo / r['file']}:{r['start_line']}) | {', '.join(r['formation_types'])} | {r['entrypoint_kind'] or '—'} | {reason} |")
        lines.append("")
    (out / "ANNOTATIONS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    lines = ["# 文件覆盖", "", "包括没有函数的文件；包内每个源码定义均有一条记录。", "", "| 文件 | 范围 | 函数 | 入口 | 非入口 | 不确定 |", "|---|---|---:|---:|---:|---:|"]
    for f in scope:
        selected = [r for r in records if r["file"] == f["file"]]
        c = counts(selected)
        lines.append(f"| {f['file']} | {f['partition']} | {f['functions']} | {c['entrypoints'] if f['in_scope'] else '—'} | {c['non_entrypoints'] if f['in_scope'] else '—'} | {c['uncertain'] if f['in_scope'] else '—'} |")
    (out / "FILE_COVERAGE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=HERE.parent / "artifacts/django-helpdesk-uast/index")
    parser.add_argument("--out", type=Path, default=HERE / "annotations/django-helpdesk-application-v1")
    args = parser.parse_args()
    if not (args.out / "POLICY.md").exists():
        raise ValueError("Freeze the annotation policy before building")
    graph = ContextGraph(args.index)
    commit = subprocess.check_output(["git", "-C", str(graph.repo), "rev-parse", "HEAD"], text=True).strip()
    if commit != EXPECTED_COMMIT or graph.summary.get("commit") != commit:
        raise ValueError("This reviewed policy/builder is pinned to " + EXPECTED_COMMIT)
    if graph.summary.get("source_roots") != ["src"] or graph.summary.get("application_roots") != ["src/helpdesk"]:
        raise ValueError("Build the index with --source-root src --application-root src/helpdesk")
    review = HelpdeskReview(graph)
    records = review.records()
    print(json.dumps(write_outputs(args.out, records, graph, review.dispatch_inventory), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
