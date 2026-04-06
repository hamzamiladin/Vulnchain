// Joern CPG script: detect Server-Side Template Injection (SSTI)
// Traces user-controlled input flowing into template rendering engines:
// Java: Thymeleaf, FreeMarker, Velocity, Pebble
// Python: Jinja2, Mako, Genshi (via CPG cross-language support)
// Node.js: Handlebars, Pug, EJS, Nunjucks
// Reduces false positives by requiring the source to be a request parameter
// and the sink to be an engine evaluate/process/render call.

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // Template engine rendering sinks
  val templateSinks =
    "(process|render|evaluate|evaluate_expression|evaluate_template|" +
    "createTemplate|compile|parse|renderToString|renderTemplate|" +
    "TemplateEngine|fromTemplate|merge|getTemplate|" +
    // Thymeleaf
    "parseExpression|process|processThymeleafView|" +
    // FreeMarker
    "getTemplate|createConfiguration|" +
    // Velocity
    "mergeTemplate|evaluate|" +
    // Node: Pug / EJS / Handlebars / Nunjucks
    "compile|render|renderFile|" +
    // Jinja2 / Mako
    "from_string|Template|render_template_string).*"

  // User-controlled sources — request parameters and body fields
  val userSources =
    "(getParameter|getHeader|getQueryString|getBody|" +
    "getAttribute|getCookies|getRequestURI|getPathInfo|" +
    // Spring / JAX-RS
    "RequestParam|PathVariable|RequestBody|" +
    // Python/Flask
    "request\\.args|request\\.form|request\\.json|request\\.data|" +
    // Express / Koa
    "req\\.query|req\\.body|req\\.params|ctx\\.query|ctx\\.request\\.body).*"

  val results = cpg.call
    .name(templateSinks)
    .where(
      _.argument.reachableBy(
        cpg.call.name(userSources)
      )
    )
    .map(c => {
      val file      = escape(c.file.name.headOption.getOrElse("unknown"))
      val line      = c.lineNumber.getOrElse(-1)
      val method    = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"critical","rule":"template-injection","source":"request-parameter"}"""
    })
    .l

  val json = "[" + results.distinct.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
