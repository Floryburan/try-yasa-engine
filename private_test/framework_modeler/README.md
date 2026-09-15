# 多语言框架函数样例

这些源码用于生成 UAST、让 LLM 编写框架 checker，以及对比框架入口/source/sink 识别结果。
目录为 `private_test/framework_modeler`，与已有的 `private_test/framework-modeler` 独立，未移动旧样例。

| 目录 | 语言/框架 | 入口证据 |
| --- | --- | --- |
| java-spring-mvc | Java / Spring MVC | Spring 注解绑定控制器方法 |
| java-servlet | Java / javax.servlet | HttpServlet 继承、WebServlet 注册、doPost |
| javascript-express | JavaScript / Express | express() 实例上的路由 callback 注册 |
| javascript-egg | JavaScript / Egg | 路由文件与继承 egg.Controller 的控制器关联 |
| go-gin | Go / Gin | gin.Default() 返回对象上的 GET 注册 |
| go-net-http | Go / 标准库 net/http | ServeMux.HandleFunc 注册 |

每组包含正例以及同名方法/类/注解的负例。部分样例还包含未注册函数及跨函数数据流。
负例的判断是“不应作为目标框架的 HTTP 入口”，不代表引擎绝不能通过其他模式分析它。
`expected-semantics.json` 是人工标准答案，只用于评估，不要作为 LLM 输入。
其中预期不代表现有硬编码 checker 已支持，需分别运行 baseline/candidate 验证。

## 使用

每次将一个子目录作为 `generate_taint_checker.py --source` 的输入，不要把整个父目录一起输入。
目录输入需显式指定 `--language java`、`--language javascript` 或 `--language go`。
例如生成 Gin 样例的请求（不调用 LLM、不保存 TS）：

```bash
python3 generate_taint_checker.py \
  --source private_test/framework_modeler/go-gin \
  --language go \
  --requirement "识别 Gin 注册的 HTTP 入口、请求输入及命令执行 sink，排除本地同名方法" \
  --output /tmp/gin-example-checker.ts \
  --dry-run
```

实际生成时移除 `--dry-run` 并指定合适的输出路径。
原生配置里的 `taint_flow_generated` 固定指向 `src/checker/generated-checker.ts`，各语言共用这一输出位置。
每次生成对应语言的 checker 后需重新编译，运行时选择相同语言的 Analyzer。

## 边界与安全

- 故意包含未过滤的命令执行。仅用于静态分析，不要启动这些服务或接收真实请求。
- 未提供依赖锁文件、应用启动配置或安装第三方依赖；这些不是完整可部署项目。
- 不需要为阅读源码安装框架；UAST 解析是否需要额外依赖取决于对应 Parser，尚未做完整解析/扫描验证。
- Java Servlet 示例选用 javax.servlet 命名空间，不是 jakarta.servlet。
- Go main 和 JavaScript 模块初始化属于启动/注册逻辑，与这里要评估的 HTTP callback 入口分开统计。
