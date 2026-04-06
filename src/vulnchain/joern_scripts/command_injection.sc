// Joern CPG script: detect command injection via taint analysis
// Tracks user-controlled data flowing into OS command execution sinks
// Supports: Java, C#, Python, JavaScript, PHP

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // OS command execution sinks
  val sinkPattern =
    "(exec|system|popen|passthru|shell_exec|proc_open|" +
    "Runtime\\.exec|ProcessBuilder|Process\\.Start|" +
    "subprocess\\.call|subprocess\\.run|subprocess\\.Popen|os\\.system|os\\.popen|" +
    "child_process\\.exec|child_process\\.execSync|child_process\\.spawn|spawnSync|" +
    "ShellExecute|CreateProcess|WinExec).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Ii]nput|.*[Rr]equest|.*[Pp]aram|.*[Qq]uery|.*[Bb]ody|" +
    ".*[Uu]ser.*|.*[Ss]earch|.*[Cc]md|.*[Cc]ommand|.*[Aa]rg|" +
    ".*[Ff]ilename|.*[Pp]ath|.*[Uu]rl).*"

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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"critical","rule":"tainted-command-injection"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
