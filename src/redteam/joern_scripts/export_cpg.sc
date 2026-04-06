// Joern CPG script: export a compact CPG summary for LLM reasoning

@main def exec(inputDir: String, outputFile: String): Unit = {
  importCode(inputDir)

  val endpoints = cpg.method
    .where(_.annotation.name("(HttpGet|HttpPost|HttpPut|HttpDelete|Route|MapGet|MapPost)"))
    .map(m => ujson.Obj(
      "type"   -> "endpoint",
      "name"   -> m.name,
      "file"   -> m.file.name.headOption.getOrElse("unknown"),
      "line"   -> m.lineNumber.getOrElse(-1),
      "params" -> ujson.Arr(m.parameter.name.l.map(ujson.Str(_))*)
    ))
    .toList

  val externalCalls = cpg.call
    .name("(HttpClient|WebClient|RestClient|fetch|axios|http\\.Get|http\\.Post).*")
    .map(c => ujson.Obj(
      "type"   -> "external_call",
      "name"   -> c.name,
      "file"   -> c.file.name.headOption.getOrElse("unknown"),
      "line"   -> c.lineNumber.getOrElse(-1)
    ))
    .toList

  val summary = ujson.Obj(
    "endpoints"     -> ujson.Arr(endpoints*),
    "external_calls" -> ujson.Arr(externalCalls*)
  )
  os.write(os.Path(outputFile), ujson.write(summary))
}
