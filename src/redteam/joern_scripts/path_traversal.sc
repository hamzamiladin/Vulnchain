// Joern CPG script: detect path traversal via taint analysis
// Tracks user-controlled data flowing into file system operations
// without sanitization (e.g., Path.normalize, realpath, basename)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // File system sinks — read, write, open, delete across languages
  val sinkPattern =
    "(open|fopen|file_get_contents|file_put_contents|readFile|writeFile|" +
    "FileInputStream|FileOutputStream|FileReader|FileWriter|" +
    "File\\.ReadAllText|File\\.WriteAllText|File\\.Open|File\\.Delete|" +
    "path\\.join|fs\\.readFile|fs\\.writeFile|fs\\.unlink|" +
    "createReadStream|createWriteStream|sendFile|res\\.download).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Ff]ilename|.*[Ff]ile[Nn]ame|.*[Pp]ath|.*[Ff]ile|.*[Nn]ame|" +
    ".*[Rr]equest|.*[Pp]aram|.*[Qq]uery|.*[Uu]rl|.*[Uu]ri|" +
    ".*[Ii]nput|.*[Uu]ser.*).*"

  // Sanitizer calls — if present in a flow, it is likely safe
  val sanitizerPattern =
    "(realpath|basename|normalize|sanitize|resolve).*"

  val results = cpg.call
    .name(sinkPattern)
    .where(arg =>
      arg.argument.reachableBy(
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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"tainted-path-traversal"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
