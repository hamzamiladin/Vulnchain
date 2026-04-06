// Joern CPG script: detect open redirect vulnerabilities
// Tracks user-controlled URLs flowing into HTTP redirect responses
// Supports: Java (HttpServletResponse.sendRedirect), C# (Response.Redirect),
//           Python (Flask redirect), JavaScript (res.redirect)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // HTTP redirect sinks
  val redirectSinks =
    "(sendRedirect|Redirect|redirect|" +
    "Response\\.Redirect|HttpResponseRedirect|" +
    "res\\.redirect|response\\.redirect|" +
    "header.*Location|Location|" +
    "moved_permanently|found).*"

  // User-controlled source parameters — especially URL-like names
  val sourcePattern =
    "(.*[Uu]rl|.*[Uu]ri|.*[Rr]edirect|.*[Rr]eturn[Uu]rl|.*[Nn]ext|" +
    ".*[Cc]allback|.*[Dd]estination|.*[Tt]arget|.*[Ll]ocation|" +
    ".*[Rr]equest|.*[Pp]aram|.*[Qq]uery|.*[Ii]nput).*"

  // Sanitizers — URL validation / allowlist checks
  val sanitizerPattern =
    "(isValidRedirect|allowedDomains|whitelist|allowlist|" +
    "validateUrl|validateRedirect|isSafeUrl|is_safe_url|" +
    "url_is_safe|url_has_allowed_host_and_scheme).*"

  val results = cpg.call
    .name(redirectSinks)
    .where(
      _.argument.reachableBy(
        cpg.method.parameter.where(_.name(sourcePattern))
      )
    )
    .whereNot(
      _.argument.reachableBy(
        cpg.call.name(sanitizerPattern)
      )
    )
    .map(c => {
      val file = escape(c.file.name.headOption.getOrElse("unknown"))
      val line = c.lineNumber.getOrElse(-1)
      val method = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"open-redirect"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
