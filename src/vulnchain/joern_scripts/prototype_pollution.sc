// Joern CPG script: detect Prototype Pollution
// Traces user-controlled data flowing into deep-merge/extend/set operations
// where the key path is not validated against __proto__, constructor, prototype.
// Covers: lodash _.merge/_.set/_.assignIn, jQuery $.extend(true, ...),
//         plain Object.assign, and custom recursive merge patterns.
// References: CVE-2025-13465 (lodash), CVE-2019-10744 (lodash), CVE-2019-11358 (jQuery)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // Deep-merge / property-set sinks that can pollute Object.prototype
  val mergeSinks =
    "(merge|mergeWith|defaultsDeep|assignIn|assignInWith|" +
    "set|setWith|" +          // lodash _.set(obj, path, value)
    "extend|deepExtend|" +    // jQuery $.extend(true, ...) and variants
    "deepMerge|deepAssign|recursiveMerge|deepClone|" +
    "assign|Object\\.assign).*"

  // User-controlled request body / query sources
  val userSources =
    "(getParameter|getBody|getQueryString|" +
    "req\\.body|req\\.query|req\\.params|" +
    "request\\.json|request\\.form|request\\.args|" +
    "JSON\\.parse|body-parser|express\\.json|" +
    "ctx\\.request\\.body|event\\.body).*"

  val results = cpg.call
    .name(mergeSinks)
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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"prototype-pollution","source":"request-body"}"""
    })
    .l

  val json = "[" + results.distinct.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
