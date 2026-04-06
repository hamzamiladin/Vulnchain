// Joern CPG script: detect Server-Side Request Forgery (SSRF) via taint analysis
// Tracks user-controlled URLs flowing into HTTP client calls
// Supports: Java, C#, Python (requests/httpx), JavaScript (fetch/axios/node-fetch)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // HTTP client sinks — outbound network calls
  val sinkPattern =
    "(HttpClient|WebClient|RestTemplate|OkHttpClient|" +
    "HttpWebRequest|WebRequest\\.Create|" +
    "requests\\.get|requests\\.post|requests\\.put|requests\\.request|" +
    "httpx\\.get|httpx\\.post|httpx\\.AsyncClient|" +
    "fetch|axios|axios\\.get|axios\\.post|" +
    "http\\.get|http\\.request|https\\.get|https\\.request|" +
    "got|needle|superagent|node-fetch|" +
    "curl_exec|curl_setopt|file_get_contents).*"

  // User-controlled source parameters (especially URL-like names)
  val sourcePattern =
    "(.*[Uu]rl|.*[Uu]ri|.*[Ee]ndpoint|.*[Hh]ost|.*[Tt]arget|" +
    ".*[Rr]edirect|.*[Cc]allback|.*[Ww]ebhook|.*[Pp]roxy|" +
    ".*[Rr]equest|.*[Pp]aram|.*[Qq]uery|.*[Ii]nput).*"

  val results = cpg.call
    .name(sinkPattern)
    .where(
      _.argument.reachableBy(
        cpg.method.parameter.where(_.name(sourcePattern))
      )
    )
    .map(c => {
      val file = escape(c.file.name.headOption.getOrElse("unknown"))
      val line = c.lineNumber.getOrElse(-1)
      val method = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"tainted-ssrf"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
