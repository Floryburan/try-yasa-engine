#!/usr/bin/env python3
"""Build an auditable CTFd static reference set, without reading model predictions."""

import argparse
import ast
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from context_graph import ContextGraph, fingerprint

HERE = Path(__file__).resolve().parent
FORMATIONS = ("registration", "inheritance", "interface_implementation", "configuration", "callback", "decorator", "other")
KINDS = ("http", "rpc", "cli", "event", "lifecycle", "other")


class ReferenceReview:
    def __init__(self, graph):
        self.graph = graph
        self.functions = graph.select_functions("application")
        self.by_name = defaultdict(list)
        self.trees, self.parents, self.lines = {}, {}, {}
        self.judgments = defaultdict(list)
        for row in self.functions:
            self.by_name[(row["file"], row["lexical_name"])].append(row)
        self.templates = []
        for path in sorted((graph.repo / "CTFd/themes").rglob("*.html")):
            self.templates.append((str(path.relative_to(graph.repo)), path.read_text(encoding="utf-8")))

    def syntax(self, file):
        if file not in self.trees:
            source = (self.graph.repo / file).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=file)
            self.trees[file] = tree
            self.lines[file] = source.splitlines(keepends=True)
            self.parents[file] = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        return self.trees[file]

    def definition(self, row):
        tree = self.syntax(row["file"])
        nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == row["name"] and n.lineno == row["start_line"]]
        if len(nodes) != 1:
            raise ValueError("Cannot locate source function: " + row["qualified_name"])
        node = nodes[0]
        first = min([node.lineno] + [d.lineno for d in node.decorator_list])
        actual = "".join(self.lines[row["file"]][first - 1:node.end_lineno])
        if actual.rstrip() != row["source"].rstrip():
            raise ValueError("Definition source mismatch: " + row["qualified_name"])
        return node

    def evidence(self, file, first, last=None, role="dispatch"):
        if file not in self.lines:
            self.lines[file]=(self.graph.repo/file).read_text(encoding="utf-8").splitlines(keepends=True)
        last = first if last is None else last
        source = "".join(self.lines[file][first-1:last])
        return {"file": file, "start_line": first, "end_line": last, "role": role,
                "source": source, "sha256": hashlib.sha256(source.encode()).hexdigest()}

    def find(self, file, needle, role="dispatch"):
        self.syntax(file)
        matches = [i for i, line in enumerate(self.lines[file], 1) if needle in line]
        if not matches:
            raise ValueError("Missing evidence: {} {}".format(file, needle))
        return self.evidence(file, matches[0], role=role)

    def mark(self, row, decision, types, kind, subtype, reason, evidence, activation="在相关应用/扩展配置启用时"):
        if decision is True and (not types or not evidence or kind not in KINDS):
            raise ValueError("Positive annotation needs dispatch evidence and labels")
        self.judgments[row["id"]].append({"is_entrypoint": decision, "formation_types": list(types),
            "entrypoint_kind": kind, "subtype": subtype, "reason": reason,
            "evidence": evidence, "activation": activation})

    def label(self, file, name, decision, types, kind, subtype, reason, references, activation="在相关应用/扩展配置启用时"):
        matches = self.by_name[(file, name)]
        if len(matches) != 1:
            raise ValueError("Non-unique reviewed target: " + str((file, name)))
        evidence = [self.find(f, needle) for f, needle in references]
        self.mark(matches[0], decision, types, kind, subtype, reason, evidence, activation)

    def automatic_evidence(self):
        # These extractors implement the explicitly documented, source-reviewed
        # CTFd registration patterns. They do not infer truth from model outputs.
        root = "CTFd/__init__.py"
        for row in self.functions:
            node = self.definition(row)
            owner = self.parents[row["file"]].get(node)
            for decorator in node.decorator_list:
                text = ast.unparse(decorator)
                ev = self.evidence(row["file"], decorator.lineno, decorator.end_lineno, "binding_decorator")
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "route":
                    receiver = ast.unparse(decorator.func.value)
                    blueprint = self.find(root, "app.register_blueprint(" + receiver + ")")
                    self.mark(row, True, ["decorator"], "http", "flask_route",
                              "路由装饰器绑定目标函数，承载 Blueprint 被应用注册。", [ev, blueprint])
                elif text.startswith("_cli.cli.command("):
                    self.mark(row, True, ["decorator"], "cli", "click_command",
                              "Blueprint CLI command 装饰器绑定目标；init_cli 将命令 Blueprint 加入应用。",
                              [ev, self.find("CTFd/utils/initialization/__init__.py", "app.register_blueprint(_cli")])
                elif text in {"app.before_request", "app.after_request", "app.url_defaults", "current_app.url_defaults"}:
                    self.mark(row, True, ["callback", "decorator"], "lifecycle", "flask_request_hook",
                              "Flask 请求/响应或 URL 构造钩子直接调度目标函数。", [ev])
                elif text in {"pre_load", "post_dump"} and row["file"].startswith("CTFd/schemas/"):
                    self.mark(row, True, ["callback", "decorator"], "other", "marshmallow_hook",
                              "Marshmallow schema 的加载/导出钩子；并非独立 HTTP endpoint。", [ev])
                elif text.startswith('validates(') and row["file"] == "CTFd/models/__init__.py":
                    self.mark(row, True, ["callback", "decorator"], "other", "sqlalchemy_attribute_validator",
                              "SQLAlchemy validates 装饰器注册属性校验回调。", [ev])
                elif text.startswith("compiles("):
                    self.mark(row, True, ["callback", "decorator"], "other", "sqlalchemy_compiler_hook",
                              "SQLAlchemy 编译扩展装饰器注册数据库类型编译回调。", [ev])
                elif text.startswith("event.listens_for("):
                    self.mark(row, True, ["callback", "decorator"], "event", "sqlalchemy_connect_listener",
                              "数据库 connect 事件监听器，由 SQLAlchemy 事件系统调用。", [ev], "SQLite 分支启用时")
            if isinstance(owner, ast.ClassDef) and row["file"].startswith("CTFd/api/v1/") and row["name"] in {"get","post","put","patch","delete","head","options"}:
                routes = [d for d in owner.decorator_list if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route"]
                if not routes:
                    continue
                if "Resource" not in [ast.unparse(b) for b in owner.bases]:
                    raise ValueError("Review unexpected API base: " + row["qualified_name"])
                for route in routes:
                    namespace = ast.unparse(route.func.value)
                    registration_file = "CTFd/api/__init__.py"
                    self.mark(row, True, ["inheritance","decorator"], "http", "flask_restx_resource_method",
                              "Resource 子类由 Namespace.route 绑定；框架按 HTTP 方法名调度目标。Resource 继承不自动等于独立接口实现。",
                              [self.evidence(row["file"], route.lineno, route.end_lineno, "resource_binding"),
                               self.find(registration_file, ".add_namespace(" + namespace), self.find(root, "app.register_blueprint(api)")])

        # Named template globals, filter mappings and validation callbacks.
        for file in ("CTFd/utils/initialization/__init__.py", "CTFd/plugins/__init__.py"):
            for call in [r for r in self.graph.tables["calls"] if r["file"] == file and r["callee"] == "app.jinja_env.globals.update"]:
                tree = self.syntax(file)
                matches = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == call["start_line"]
                           and ast.unparse(n.func) == "app.jinja_env.globals.update"]
                for call_node in matches:
                    for keyword in call_node.keywords:
                        if not isinstance(keyword.value, (ast.Name, ast.Attribute)):
                            continue
                        ids, _, _ = self.graph.resolve(ast.unparse(keyword.value), file, call.get("scope_id"), call["start_line"])
                        for target_id in ids:
                            target = self.graph.nodes[target_id]
                            if target.get("record_type") == "functions" and target.get("area") == "application":
                                self.mark(target, True, ["registration","callback"], "other", "jinja_global_function",
                                          "目标函数明确加入 Jinja globals，可由模板调用；其普通 Python 调用不是额外入口。",
                                          [self.evidence(file, call["start_line"], call["end_line"], "template_registration")])
        for assignment in self.graph.tables["assignments"]:
            if assignment["file"] == "CTFd/utils/initialization/__init__.py" and assignment["target"].startswith("app.jinja_env.filters["):
                ids, _, _ = self.graph.resolve(assignment["value"], assignment["file"], assignment.get("scope_id"), assignment["start_line"])
                for target_id in ids:
                    target = self.graph.nodes[target_id]
                    if target.get("record_type") == "functions":
                        self.mark(target, True, ["configuration","callback"], "other", "jinja_filter",
                                  "函数写入 Jinja filters 配置字典，作为模板过滤器被调用。",
                                  [self.evidence(assignment["file"], assignment["start_line"], assignment["end_line"], "filter_mapping")])
        for call in self.graph.tables["calls"]:
            if call.get("area")!="application" or call["callee"] not in {"render_template","render_template_string"}:
                continue
            self.syntax(call["file"])
            nodes=[n for n in ast.walk(self.trees[call["file"]]) if isinstance(n,ast.Call)
                   and n.lineno==call["start_line"] and ast.unparse(n.func)==call["callee"]]
            for node in nodes:
                for keyword in node.keywords:
                    if not isinstance(keyword.value,(ast.Name,ast.Attribute)):
                        continue
                    ids,_,_=self.graph.resolve(ast.unparse(keyword.value),call["file"],call.get("scope_id"),call["start_line"])
                    for target_id in ids:
                        target=self.graph.nodes[target_id]
                        if target.get("record_type")=="functions" and target.get("area")=="application":
                            self.mark(target,True,["registration","callback"],"other","jinja_context_function",
                                      "可调用对象作为 render_template 上下文参数交给模板引擎，区别于在参数中立即调用函数取得结果。",
                                      [self.evidence(call["file"],call["start_line"],call["end_line"],"template_context_binding")])

    def explicit_reviews(self):
        label = self.label
        root = "CTFd/__init__.py"
        for lexical, needle in (("register_plugin_assets_directory.assets_handler","view_func=assets_handler"),
                                ("register_plugin_asset.asset_handler","view_func=asset_handler")):
            label("CTFd/plugins/__init__.py", lexical, True, ["registration"], "http", "registered_asset_handler",
                  "add_url_rule 的 view_func 指向目标逻辑处理函数；外层注册辅助函数不因此成为入口。",
                  [("CTFd/plugins/__init__.py",needle)])
        label("CTFd/errors.py","render_error",True,["registration","callback"],"http","flask_error_handler",
              "同一函数被注册处理多个 HTTP 错误码，按函数定义只记一条。",[(root,"app.register_error_handler(code, render_error)")])
        label("CTFd/__init__.py","create_app",True,["other"],"lifecycle","application_factory",
              "部署启动模块选择此函数创建 WSGI 应用；普通 init_* 辅助函数不继承其入口身份。",[("wsgi.py","app = create_app()"),("serve.py","app = create_app()")])
        hooks = {
            "CTFdRequest.__init__":("request_class = CTFdRequest",["inheritance","configuration","callback"],"flask_request_factory"),
            "CTFdFlask.create_jinja_environment":("app = CTFdFlask(__name__)",["inheritance","callback"],"flask_environment_hook"),
            "CTFdFlask.create_url_adapter":("app = CTFdFlask(__name__)",["inheritance","callback"],"flask_url_adapter_hook"),
            "SandboxedBaseEnvironment.__init__":("jinja_environment = SandboxedBaseEnvironment",["inheritance","configuration","callback"],"jinja_environment_factory"),
            "SandboxedBaseEnvironment._load_template":("jinja_environment = SandboxedBaseEnvironment",["inheritance","configuration","callback"],"jinja_environment_hook"),
            "ThemeLoader.get_source":("app.jinja_loader = jinja2.ChoiceLoader(loaders)",["inheritance","interface_implementation","configuration","callback"],"jinja_loader_hook")}
        for name,(needle,types,subtype) in hooks.items():
            label(root,name,True,types,"lifecycle" if subtype.startswith("flask_") or subtype.endswith("factory") else "other",subtype,
                  "具体扩展类型已装入 Flask/Jinja 配置，目标是框架调用的构造/覆盖钩子；非仅凭继承判正。",[(root,needle)])
        for method in ("open_session","save_session"):
            label("CTFd/utils/sessions/__init__.py","CachingSessionInterface."+method,True,
                  ["inheritance","interface_implementation","configuration","callback"],"lifecycle","flask_session_interface",
                  "Flask session_interface 明确设置为 CachingSessionInterface，框架在请求生命周期调用 open/save_session。",[(root,"self.session_interface = CachingSessionInterface")])
        label("CTFd/config.py","EnvInterpolation.before_get",True,["inheritance","configuration","callback"],"lifecycle","configparser_interpolation",
              "ConfigParser 的 interpolation 槽设置为 EnvInterpolation，配置读取时回调 before_get。",[("CTFd/config.py","ConfigParser(interpolation=EnvInterpolation())")])
        label("CTFd/forms/__init__.py","CTFdCSRF.generate_csrf_token",True,["inheritance","interface_implementation","configuration","callback"],"other","wtforms_csrf_hook",
              "BaseForm.Meta.csrf_class 指定 CTFdCSRF，由 WTForms CSRF 流程调用目标方法。",[("CTFd/forms/__init__.py","csrf_class = CTFdCSRF")])
        label("CTFd/forms/fields.py","SubmitField.__init__",True,["inheritance","configuration","callback"],"other","wtforms_bound_field_factory",
              "自定义字段类型用于表单声明，WTForms 将 UnboundField 绑定到表单时构造此字段实例；与普通服务对象显式初始化区分。",[("CTFd/forms/auth.py","submit = SubmitField("),("CTFd/forms/fields.py","class SubmitField(_SubmitField)")])
        label("CTFd/schemas/config.py","ConfigValueField._deserialize",True,["inheritance","interface_implementation","configuration","callback"],"other","marshmallow_field_deserializer",
              "自定义字段绑定到 ConfigSchema.value，Marshmallow 字段加载管线调用 _deserialize。",[("CTFd/schemas/config.py","value = ConfigValueField(")])
        label("CTFd/schemas/challenges.py","ChallengeRequirementsValidator.__call__",True,["inheritance","interface_implementation","configuration","callback"],"other","marshmallow_validator",
              "校验器实例被放入 requirements 字段 validate 列表，框架调用 __call__。",[("CTFd/schemas/challenges.py","validate=[ChallengeRequirementsValidator()]")])
        for name in ("validate_country_code","validate_language"):
            label("CTFd/utils/validators/__init__.py",name,True,["configuration","callback"],"other","marshmallow_field_validator",
                  "函数实际出现在 schema 字段 validate 列表；其他普通 validate_* 工具函数不能按名字判正。",
                  [("CTFd/schemas/users.py","validate=["+name+"]")])
        for name in ("UserSchema.__init__","TeamSchema.__init__"):
            file="CTFd/schemas/"+("users.py" if name.startswith("User") else "teams.py")
            label(file,name,True,["inheritance","configuration","callback"],"other","marshmallow_nested_schema_factory",
                  "Schema 类型作为 fields.Nested 的类参数，框架可延迟构造实例，目标构造器有外部框架调用路径。",
                  [("CTFd/schemas/submissions.py","fields.Nested("+name.split('.')[0])])
        label("CTFd/utils/user/__init__.py","get_locale",True,["configuration","callback"],"lifecycle","babel_locale_selector",
              "Babel locale_selector_func 槽直接指向此函数；它另有模板全局函数绑定。",[(root,"babel.locale_selector_func = get_locale")])
        label("CTFd/cache/__init__.py","make_cache_key",True,["configuration","callback"],"other","flask_caching_key_callback",
              "ScoreboardList.get 的 cache.cached(key_prefix=make_cache_key) 提交此函数作为键回调。",[("CTFd/api/v1/scoreboard.py","key_prefix=make_cache_key")])
        label("CTFd/events/__init__.py","subscribe.gen",True,["callback","decorator"],"http","streaming_response_body",
              "生成器被 stream_with_context 包装，并提交 Response 作为流式响应体；与普通内部 generator 区分。",[("CTFd/events/__init__.py","Response(gen()")])
        label("CTFd/utils/events/__init__.py","RedisEventManager.listen._listen",True,["registration","callback"],"event","gevent_task",
              "目标提交给 gevent.spawn 作为独立后台执行任务；retry 装饰器本身不是入口来源。",[("CTFd/utils/events/__init__.py","spawn(_listen)")],"CACHE_TYPE=redis 时")
        for cls in ("EventManager","RedisEventManager"):
            for method in ("publish","listen","subscribe"):
                file={"publish":"CTFd/api/v1/notifications.py","listen":"CTFd/utils/initialization/__init__.py","subscribe":"CTFd/events/__init__.py"}[method]
                label("CTFd/utils/events/__init__.py",cls+"."+method,True,
                      (["inheritance","configuration"] if cls=="RedisEventManager" else ["configuration"]),
                      "lifecycle" if method=="listen" else "event","configured_event_manager",
                      "init_events 按 CACHE_TYPE 安装事件管理器实现，应用通过 events_manager 的统一契约调度目标。",
                      [("CTFd/utils/initialization/__init__.py","app.events_manager = "+cls+"()"),(file,"events_manager."+method+"(")],
                      "对应 CACHE_TYPE 选择该实现时")
        label("CTFd/cli/__init__.py","jsenums",True,["configuration","callback"],"cli","cli_subcommand_dispatch",
              "BUILD_COMMANDS 显式选择子命令，再由 build(cmd) 调度。",[("CTFd/cli/__init__.py",'BUILD_COMMANDS = {"jsenums"'),("CTFd/cli/__init__.py","cmd = BUILD_COMMANDS.get(cmd)")])

        # CTFd extension dispatch: method implementation + actual configured
        # receiver + dispatch site, rather than all methods of a subclass.
        plugin_methods=("create","read","update","delete","attempt","partial","ratelimited","solve","fail")
        for method in plugin_methods:
            label("CTFd/plugins/challenges/__init__.py","BaseChallenge."+method,True,["inheritance","configuration"],"other","challenge_plugin_method",
                  "CHALLENGE_CLASSES 注册的具体题目类继承本实现，API 的题目插件调度明确调用该方法。",
                  [("CTFd/plugins/challenges/__init__.py",'CHALLENGE_CLASSES = {"standard"'),("CTFd/api/v1/challenges.py","."+method+"(")])
        for method in ("read","update","solve"):
            label("CTFd/plugins/dynamic_challenges/__init__.py","DynamicValueChallenge."+method,True,["inheritance","configuration"],"other","challenge_plugin_method",
                  "dynamic 注册类覆盖题目插件调度契约，由 API 选择后调用；calculate_value 是其内部辅助方法。",
                  [("CTFd/plugins/dynamic_challenges/__init__.py",'CHALLENGE_CLASSES["dynamic"]'),("CTFd/api/v1/challenges.py","."+method+"(")])
        for cls in ("CTFdStaticFlag","CTFdRegexFlag"):
            label("CTFd/plugins/flags/__init__.py",cls+".compare",True,["inheritance","configuration"],"other","flag_plugin_method",
                  "FLAG_CLASSES 注册具体 Flag 类型，判题调度选择类型并调用 compare。",
                  [("CTFd/plugins/flags/__init__.py","FLAG_CLASSES ="),("CTFd/plugins/challenges/logic.py","get_flag_class(flag.type).compare")])
        for file in ("CTFd/plugins/challenges/__init__.py","CTFd/plugins/dynamic_challenges/__init__.py","CTFd/plugins/flags/__init__.py"):
            label(file,"load",True,["callback"],"lifecycle","plugin_loader_hook",
                  "init_plugins 导入插件模块后按 load(app) 约定调度目标。",[("CTFd/plugins/__init__.py","module.load(app)")],"SAFE_MODE=False 且插件启用时")
        for file in ("CTFd/plugins/challenges/decay.py","CTFd/plugins/dynamic_challenges/decay.py"):
            caller="CTFd/plugins/challenges/__init__.py" if "/dynamic_" not in file else "CTFd/plugins/dynamic_challenges/__init__.py"
            for name in ("linear","logarithmic"):
                label(file,name,True,["configuration","callback"],"other","challenge_scoring_strategy",
                      "DECAY_FUNCTIONS 映射选择评分策略，调度器以 f(challenge) 调用；get_solve_count 是内部工具。",
                      [(file,"DECAY_FUNCTIONS ="),(caller,"f = DECAY_FUNCTIONS.get")])
        for cls in ("FilesystemUploader","S3Uploader"):
            for method in ("store","upload","download","delete","sync","open"):
                # The store call from upload is also a helper call, but import
                # dispatch separately invokes uploader.store at the boundary.
                dispatch_file = {"store":"CTFd/utils/exports/__init__.py","upload":"CTFd/utils/uploads/__init__.py",
                                 "download":"CTFd/views.py","delete":"CTFd/utils/uploads/__init__.py",
                                 "sync":"CTFd/utils/exports/__init__.py","open":"CTFd/utils/social/__init__.py"}[method]
                label("CTFd/utils/uploads/uploaders.py",cls+"."+method,True,["inheritance","interface_implementation","configuration"],"other","configured_uploader_method",
                      "UPLOADERS/UPLOAD_PROVIDER 选择具体 BaseUploader 实现，边界调用者通过统一接口调度目标。",
                      [("CTFd/utils/uploads/__init__.py","UPLOADERS ="),(dispatch_file,"uploader."+method+"(")],"对应 UPLOAD_PROVIDER 配置启用时")
        for cls,file in (("SMTPEmailProvider","smtp.py"),("MailgunEmailProvider","mailgun.py")):
            label("CTFd/utils/email/providers/"+file,cls+".sendmail",True,["inheritance","interface_implementation","configuration"],"other","configured_email_provider",
                  "PROVIDERS 选择 EmailProvider 实现，再通过 sendmail 契约调度。",[("CTFd/utils/email/__init__.py","PROVIDERS ="),("CTFd/utils/email/__init__.py","return EmailProvider.sendmail(")])
        for row in self.functions:
            if "/dynamic_challenges/migrations/" in row["file"]:
                if row["name"]=="upgrade":
                    self.mark(row,True,["callback"],"lifecycle","plugin_migration_upgrade",
                              "插件迁移加载器逐 revision 显式调用 module.upgrade(op=op)。",
                              [self.find("CTFd/plugins/migrations.py","r.module.upgrade(op=op)")],"插件迁移且非 SQLite 分支时")
                else:
                    self.mark(row,None,["callback"],None,"unconfirmed_migration_downgrade",
                              "存在 Alembic 风格 downgrade 定义，但仓库插件加载器仅实现 upgrade；未确认部署中的回滚调度路径。",
                              [self.find("CTFd/plugins/migrations.py","r.module.upgrade(op=op)")])

    def template_namespace_reviews(self):
        init="CTFd/utils/initialization/__init__.py"
        for row in self.functions:
            file, lexical = row["file"],row["lexical_name"]
            expression=None
            if file.startswith("CTFd/forms/") and "." not in lexical and row["name"].endswith("Form"):
                expression="Forms."+Path(file).stem+"."+row["name"]
                references=[self.find(init,"app.jinja_env.globals.update(Forms=Forms)"),self.find("CTFd/forms/__init__.py","Forms."+Path(file).stem+" =")]
            elif file in {"CTFd/utils/config/__init__.py","CTFd/utils/config/integrations.py"} and "." not in lexical:
                ns="config" if file.endswith("/__init__.py") else "integrations"
                expression=ns+"."+row["name"]
                references=[self.find(init,"app.jinja_env.globals.update("+ns+"="+ns+")")]
            elif file.startswith("CTFd/constants/"):
                namespaces={"_AssetsWrapper":"Assets","_ConfigsWrapper":"Configs","_PluginWrapper":"Plugins",
                            "_SessionWrapper":"Session","_TeamAttrsWrapper":"Team","_UserAttrsWrapper":"User"}
                parts=lexical.split(".")
                if len(parts)==2 and parts[0] in namespaces and (not parts[1].startswith("_") or parts[1]=="__getattr__"):
                    ns=namespaces[parts[0]]
                    expression=ns+"."+parts[1]
                    references=[self.find(init,"app.jinja_env.globals.update("+ns+"="+ns+")")]
            if not expression:
                continue
            hits=[]
            for template,text in self.templates:
                for line,content in enumerate(text.splitlines(),1):
                    matches = bool(re.search(r"(?<![A-Za-z_0-9])"+re.escape(expression)+r"\b",content))
                    if row["name"]=="__getattr__":
                        owner=self.parents[file].get(self.definition(row))
                        defined={n.name for n in owner.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
                        matches=any(name not in defined for name in re.findall(re.escape(expression.rsplit('.',1)[0])+r"\.([A-Za-z_]\w*)",content))
                    if matches:
                        hits.append(self.evidence(template,line,role="template_use"))
                        break
                if len(hits)>=2:
                    break
            if hits:
                self.mark(row,True,["configuration","callback"],"other","jinja_namespace_member",
                          "目标所属命名空间明确暴露到 Jinja globals，仓库模板直接引用该函数或导出的属性。模板数据对象的一般属性不按此规则扩张。",
                          references+hits)
            elif row["id"] not in self.judgments:
                self.mark(row,None,["configuration","callback"],None,"unused_exported_template_member",
                          "函数/成员可经导出模板命名空间访问，但未找到仓库自带模板的实际引用；外部主题是否使用未知。",references)

    def boundary_reviews(self):
        for assignment in self.graph.tables["assignments"]:
            if not assignment["file"].startswith("CTFd/schemas/") or assignment["target"]!="model":
                continue
            ids,_,_=self.graph.resolve(assignment["value"],assignment["file"],assignment.get("scope_id"),assignment["start_line"])
            for class_id in ids:
                cls=self.graph.nodes[class_id]
                if cls.get("record_type")!="classes" or cls["file"]!="CTFd/models/__init__.py":
                    continue
                for function_id in self.graph.members.get((class_id,"__init__"),[]):
                    target=self.graph.nodes[function_id]
                    if target.get("origin")!="source_definition":
                        continue
                    self.mark(target,None,["inheritance","configuration","callback"],None,"orm_schema_construction_boundary",
                              "Schema.Meta.model 指定该模型，Marshmallow 可在 load 时间接创建它；是否将数据对象构造纳入应用入口存在范围边界，需独立复核，不能按普通构造器直接判负。",
                              [self.evidence(assignment["file"],assignment["start_line"],assignment["end_line"],"schema_model_binding")])
        cases=[("CTFd/utils/sessions/__init__.py","CachedSession.__init__.on_update",["callback"],
                "内部 CallbackDict 更新回调，是否把此类存储维护回调纳入应用入口需独立复核。",[("CTFd/utils/sessions/__init__.py","CallbackDict.__init__(self, initial, on_update)")]),
               ("CTFd/utils/exports/serializers.py","JSONEncoder.default",["inheritance","configuration","callback"],
                "导出时 json.dumps(cls=JSONEncoder) 的编码器回调；内部序列化回调与应用调度入口的边界保留不确定。",[("CTFd/utils/exports/serializers.py","cls=JSONEncoder")])]
        for file,name,types,reason,refs in cases:
            self.label(file,name,None,types,None,"auxiliary_library_callback_boundary",reason,refs)
        # The exported social strategy is a clear application dispatch boundary,
        # while its constructor/URL/MAC properties remain ordinary internal work.
        self.label("CTFd/utils/social/__init__.py","SolveSocialShare.asset",True,["configuration"],"other","social_share_strategy",
                   "SOCIAL_SHARES 根据请求 type 选择实现，assets 路由通过统一策略的 asset(path) 调度；此方法不是直接 HTTP endpoint。",
                   [("CTFd/utils/social/__init__.py","SOCIAL_SHARES ="),("CTFd/share.py","return s.asset(path)")])
        self.label("CTFd/utils/social/__init__.py","SolveSocialShare.content",True,["configuration"],"other","social_share_strategy",
                   "SOCIAL_SHARES 按 type 选择实现，share 路由读取统一策略的 content 结果，属于显式策略契约而非任意 property。",
                   [("CTFd/utils/social/__init__.py","SOCIAL_SHARES ="),("CTFd/share.py","return s.content")])

    def negative_role(self,row):
        file,name=row["file"],row["lexical_name"]
        node=self.definition(row)
        ds=[ast.unparse(d) for d in node.decorator_list]
        if "/tests/" in file:
            return "embedded_test", "内嵌测试运行器函数，不属于部署应用的入口范围。"
        if file.startswith("CTFd/utils/decorators/") or file=="CTFd/api/v1/helpers/request.py" or name.startswith("timed_lru_cache"):
            return "decorator_plumbing", "装饰器工厂或共享 wrapper；按逻辑处理函数口径，注册目标另有定义，不重复作为入口。"
        if (file=="CTFd/utils/uploads/uploaders.py" and name.startswith("BaseUploader.")) or file=="CTFd/utils/email/providers/__init__.py" or name=="BaseFlag.compare":
            return "unregistered_base_contract", "接口基类/默认契约未被配置注册为具体运行时实现，已注册实现另行标注。"
        if any(d in {"property","hybrid_property"} or d.endswith(".setter") for d in ds):
            return "ordinary_descriptor", "普通模型/表单/对象属性或 setter；未发现其作为独立调度契约绑定，不能仅凭属性访问判为入口。"
        if row["name"]=="__init__":
            return "internal_constructor", "由项目代码显式构造的对象初始化；没有找到框架/配置槽直接选择该构造器的独立绑定证据。"
        if row["name"].startswith("__"):
            return "language_protocol", "普通 Python 对象协议方法；没有应用级注册/配置调度证据。"
        if file.startswith("CTFd/schemas/"):
            return "schema_helper", "Schema 构造或普通方法，由项目代码直接调用；不是已注册的 schema 钩子/字段校验器。"
        if file.startswith("CTFd/forms/"):
            return "form_helper", "表单构造/字段拼装内部方法，由工厂或表单代码直接调用；没有独立框架调度绑定。"
        if file=="CTFd/models/__init__.py" or file.startswith("CTFd/plugins/dynamic_challenges/__init__"):
            return "model_or_plugin_helper", "模型数据访问或插件实现内部辅助逻辑；普通调用或继承本身不构成扩展调度入口。"
        if file=="CTFd/plugins/__init__.py" and row["name"].startswith("register_"):
            return "registration_helper", "函数注册其他 handler 或静态资源/脚本；目标本身没有因此成为请求处理函数。"
        if file.startswith("CTFd/api/v1/"):
            return "api_internal_helper", "API 的模型转换、文档或请求解析辅助函数；其调用者为处理函数，不转移入口身份。"
        if file=="CTFd/__init__.py" or file=="CTFd/utils/initialization/__init__.py":
            return "startup_helper", "由 create_app 或初始化流程显式调用的辅助函数，不是另行注册的启动/框架钩子。"
        if file.startswith("CTFd/plugins/"):
            return "plugin_internal_helper", "插件内部工具/查询/包装逻辑；未发现目标本身承担已配置的扩展调度契约。"
        return "internal_helper", "普通业务工具函数或服务对象方法；核对目标角色及静态引用后，没有确认的独立注册/配置/框架调度证据。"

    def records(self):
        self.automatic_evidence()
        self.explicit_reviews()
        self.template_namespace_reviews()
        self.boundary_reviews()
        records=[]
        for row in self.functions:
            node=self.definition(row)
            bindings=self.judgments[row["id"]]
            target_ev=self.evidence(row["file"],row.get("source_start_line",row["start_line"]),row["end_line"],"target_definition")
            if bindings:
                decisions={b["is_entrypoint"] for b in bindings}
                if True in decisions and False in decisions:
                    raise ValueError("Conflicting reviewed annotations")
                decision=True if True in decisions else None
                kinds=[k for k in KINDS if any(b["entrypoint_kind"]==k and b["is_entrypoint"] is True for b in bindings)]
                types=[t for t in FORMATIONS if any(t in b["formation_types"] and b["is_entrypoint"] is True for b in bindings)]
                reason="；".join(dict.fromkeys(b["reason"] for b in bindings))
                subtype=sorted({b["subtype"] for b in bindings})
                evidence=[target_ev]+[e for b in bindings for e in b["evidence"]]
                candidates=[t for t in FORMATIONS if any(t in b["formation_types"] for b in bindings)] if decision is None else []
            else:
                decision=False
                role,reason=self.negative_role(row)
                subtype=[role]
                kinds,types,candidates=[],[],[]
                evidence=[target_ev]
                calls=[]
                for edge in self.graph.incoming[row["id"]]:
                    caller=self.graph.nodes[edge["source"]]
                    if edge["relation"]=="calls" and caller.get("area")=="application" and caller.get("record_type")=="calls":
                        if caller["file"]==row["file"] and row["start_line"]<=caller["start_line"]<=row["end_line"]:
                            continue
                        calls.append(caller)
                for caller in sorted(calls,key=lambda r:(r["file"],r["start_line"]))[:2]:
                    evidence.append(self.evidence(caller["file"],caller["start_line"],caller["end_line"],"internal_call_site"))
            evidence=list({(e["file"],e["start_line"],e["end_line"],e["role"]):e for e in evidence}.values())
            if decision is True and "inheritance" in types:
                owner=self.graph.nodes.get(row.get("scope_id"),{})
                queue=[owner] if owner.get("record_type")=="classes" else []
                seen=set()
                while queue:
                    cls=queue.pop(0)
                    if cls["id"] in seen:
                        continue
                    seen.add(cls["id"])
                    self.syntax(cls["file"])
                    matches=[n for n in ast.walk(self.trees[cls["file"]]) if isinstance(n,ast.ClassDef) and n.lineno==cls["start_line"] and n.name==cls["name"]]
                    if len(matches)!=1:
                        raise ValueError("Unresolved inheritance evidence")
                    class_node=matches[0]
                    first=min([class_node.lineno]+[d.lineno for d in class_node.decorator_list])
                    body_first=min([n.lineno for n in class_node.body])
                    evidence.append(self.evidence(cls["file"],first,max(class_node.lineno,body_first-1),"class_contract"))
                    for edge in self.graph.outgoing[cls["id"]]:
                        related=self.graph.nodes[edge["target"]]
                        if edge["relation"]=="inherits" and related["record_type"]=="classes":
                            queue.append(related)
                        elif edge["relation"]=="binding_evidence" and related["record_type"]=="imports":
                            evidence.append(self.evidence(related["file"],related["start_line"],related["end_line"],"base_import"))
            records.append({"function_id":row["id"],"case_id":"fn_"+fingerprint(row["definition_identity"])[:24],
                "function":row["qualified_name"],"definition_identity":row["definition_identity"],
                "file":row["file"],"start_line":row["start_line"],"end_line":row["end_line"],
                "source_sha256":hashlib.sha256(row["source"].encode()).hexdigest(),
                "is_entrypoint":decision,"formation_types":types,"entrypoint_kind":kinds[0] if kinds else None,
                "entrypoint_kinds":kinds,"subtypes":subtype,"reason":reason,"evidence":evidence,
                "bindings":bindings,"candidate_formation_types":candidates,
                "annotation_origin":"agent_static_review_with_source_extractors",
                "review_status":"agent_first_pass","independent_human_review":False,
                "evidence_level":"direct_binding" if decision is True else "source_role_review" if decision is False else "unresolved_boundary",
                "review_priority":"high" if decision is None or (decision is False and len(evidence)==1) else "normal",
                "needs_independent_review":True})
        return records


def write_outputs(out,records,graph):
    def write(name,obj):
        (out/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    write("annotations.json",records)
    (out/"annotations.jsonl").write_text("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in records),encoding="utf-8")
    columns=("function_id","function","file","start_line","end_line","is_entrypoint","formation_types","candidate_formation_types",
             "entrypoint_kind","entrypoint_kinds","subtypes","reason","evidence_locations","review_priority","review_status")
    for name,items in (("annotations.csv",records),("entrypoints.csv",[r for r in records if r["is_entrypoint"] is True]),
                       ("non-entrypoints.csv",[r for r in records if r["is_entrypoint"] is False]),
                       ("uncertain.csv",[r for r in records if r["is_entrypoint"] is None])):
        with (out/name).open("w",encoding="utf-8-sig",newline="") as stream:
            writer=csv.DictWriter(stream,fieldnames=columns)
            writer.writeheader()
            for row in items:
                values={k:row.get(k,"") for k in columns}
                values["is_entrypoint"]={True:"true",False:"false",None:"unknown"}[row["is_entrypoint"]]
                for key in ("formation_types","candidate_formation_types","entrypoint_kinds","subtypes"):
                    values[key]=";".join(row[key])
                values["evidence_locations"]=";".join("{}:{}-{}".format(e["file"],e["start_line"],e["end_line"]) for e in row["evidence"])
                writer.writerow(values)
    summary={"functions":len(records),"files":len({r["file"] for r in records}),
             "entrypoints":sum(r["is_entrypoint"] is True for r in records),
             "non_entrypoints":sum(r["is_entrypoint"] is False for r in records),
             "uncertain":sum(r["is_entrypoint"] is None for r in records),
             "formation_counts":dict(Counter(t for r in records for t in r["formation_types"])),
             "kind_counts":dict(Counter(r["entrypoint_kind"] for r in records if r["is_entrypoint"] is True)),
             "subtype_counts":dict(Counter(t for r in records for t in r["subtypes"])),
             "independent_human_review":False,"model_predictions_read":False,"api_called":False}
    write("summary.json",summary)
    manifest={"annotation_version":"ctfd-application-v1","policy_sha256":hashlib.sha256((out/"POLICY.md").read_bytes()).hexdigest(),
              "builder_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "repository":str(graph.repo),"repository_commit":graph.summary.get("commit"),"index_hashes":graph.index_hashes,
              "created_at":datetime.now(timezone.utc).isoformat(),"annotation_origin":"agent_static_review_with_source_extractors",
              "independent_human_review":False,"model_predictions_read":False,"api_called":False,
              "files_sha256":{file:hashlib.sha256((graph.repo/file).read_bytes()).hexdigest() for file in sorted({e["file"] for r in records for e in r["evidence"]})}}
    write("manifest.json",manifest)
    lines=["# CTFd 逐函数静态参考标注", "", "AI 辅助源码标注，尚未经独立人工复核。范围和边界见 [POLICY.md](POLICY.md)。", "",
           "共 {} 个函数：入口 {}，非入口 {}，证据不足 {}。".format(summary["functions"],summary["entrypoints"],summary["non_entrypoints"],summary["uncertain"]),
           "", "完整可筛选表见 annotations.csv；逐条源码和绑定证据见 annotations.json。", ""]
    for decision,title in ((True,"入口"),(None,"证据不足"),(False,"非入口")):
        lines += ["## "+title,"","| 函数 | 文件位置 | 形成方式 | 用途 | 子类型 | 判断依据 |","|---|---|---|---|---|---|"]
        for row in records:
            if row["is_entrypoint"] is not decision:continue
            target="{}:{}".format(graph.repo/row["file"],row["start_line"])
            reason=row["reason"].replace("|","\\|").replace("\n"," ")
            lines.append("| `{}` | [{}:{}]({}) | {} | {} | {} | {} |".format(row["function"],row["file"],row["start_line"],target,
                         ", ".join(row["formation_types"]),row["entrypoint_kind"] or "—",", ".join(row["subtypes"]),reason))
        lines.append("")
    (out/"ANNOTATIONS.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    groups=defaultdict(list)
    for row in records:
        groups[row["file"]].append(row)
    inventory=["# 文件覆盖与复核清单","","覆盖所有目标定义；本表不表示已完成独立人工逐条复核。","",
               "| 文件 | 函数 | 入口 | 非入口 | 不确定 |","|---|---:|---:|---:|---:|"]
    for file,items in sorted(groups.items()):
        inventory.append("| {} | {} | {} | {} | {} |".format(file,len(items),sum(r["is_entrypoint"] is True for r in items),
                         sum(r["is_entrypoint"] is False for r in items),sum(r["is_entrypoint"] is None for r in items)))
    (out/"FILE_COVERAGE.md").write_text("\n".join(inventory)+"\n",encoding="utf-8")
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index",type=Path,default=HERE.parent/"artifacts/ctfd-uast/index")
    parser.add_argument("--out",type=Path,default=HERE/"annotations/ctfd-application-v1")
    args=parser.parse_args()
    if not (args.out/"POLICY.md").exists():
        raise ValueError("Write and freeze the review policy in --out first")
    graph=ContextGraph(args.index)
    review=ReferenceReview(graph)
    records=review.records()
    summary=write_outputs(args.out,records,graph)
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
