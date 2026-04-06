// Joern CPG script: detect sensitive data flowing into log statements
// Uses taint analysis — traces from user-controlled parameters with sensitive names
// to logging sinks, reducing false positives from intentional masked-value logging.

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // Logging sinks across languages
  val logSinks =
    "(log|Log|logger|Logger|console|Console|" +
    "debug|info|warn|warning|error|critical|" +
    "println|Print|WriteLine|writeLine|" +
    "echo|var_dump|print_r).*"

  // Method parameters whose names suggest they carry sensitive data.
  // Using parameter-level taint (not arbitrary identifiers) reduces false positives.
  val sensitiveParamPattern =
    "(.*[Pp]assword|.*[Pp]asswd|.*[Ss]ecret|.*[Tt]oken|" +
    ".*[Aa]pi[Kk]ey|.*[Aa]cess[Kk]ey|.*[Pp]rivate[Kk]ey|" +
    ".*[Cc]redit[Cc]ard|.*[Cc]ard[Nn]um|.*[Ss]sn|" +
    ".*[Aa]uth[Tt]oken|.*[Bb]earer[Tt]oken|" +
    ".*[Cc]redential|.*[Ss]ession[Tt]oken|" +
    ".*[Aa]ccess[Tt]oken|.*[Rr]efresh[Tt]oken).*"

  // Also catch local identifiers with sensitive names flowing to logs
  // (e.g. a local var 'password' or 'secret' passed directly to logger)
  val sensitiveIdentPattern =
    "^(password|passwd|secret|token|apiKey|api_key|accessKey|access_key|" +
    "privateKey|private_key|creditCard|ssn|authToken|bearerToken|" +
    "credential|sessionToken|accessToken|refreshToken)$"

  // Taint from sensitive-named parameters
  val paramResults = cpg.call
    .name(logSinks)
    .where(
      _.argument.reachableBy(
        cpg.method.parameter.where(_.name(sensitiveParamPattern))
      )
    )
    .map(c => {
      val file = escape(c.file.name.headOption.getOrElse("unknown"))
      val line = c.lineNumber.getOrElse(-1)
      val method = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"sensitive-data-in-logs","source":"parameter"}"""
    })
    .l

  // Taint from sensitive-named local identifiers (exact match to reduce FP)
  val identResults = cpg.call
    .name(logSinks)
    .where(
      _.argument.reachableBy(
        cpg.identifier.name(sensitiveIdentPattern)
      )
    )
    .map(c => {
      val file = escape(c.file.name.headOption.getOrElse("unknown"))
      val line = c.lineNumber.getOrElse(-1)
      val method = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"sensitive-data-in-logs","source":"identifier"}"""
    })
    .l

  val allResults = (paramResults ++ identResults).distinct
  val json = "[" + allResults.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
