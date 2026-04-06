// Joern CPG script: detect unprotected HTTP endpoints
// Checks for route handler methods missing authorization annotations/decorators

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // HTTP route annotations (Java Spring, C# ASP.NET, JAX-RS)
  val routeAnnotations =
    "(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|" +
    "Route|MapGet|MapPost|MapPut|MapDelete|" +
    "GET|POST|PUT|DELETE|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)"

  // Authorization annotations/decorators
  val authAnnotations =
    "(Authorize|AllowAnonymous|RequireAuthorization|" +
    "RolesAllowed|PermitAll|DenyAll|Secured|" +
    "PreAuthorize|PostAuthorize|login_required|requires_auth|authenticated)"

  // Methods that are public-facing by convention (skip auth check for these)
  val publicMethods =
    "(Login|Register|ForgotPassword|ResetPassword|" +
    "Health|Status|Ping|Index|Home|About|" +
    "login|register|logout|health|ping).*"

  val results = cpg.method
    .where(_.annotation.name(routeAnnotations))
    .whereNot(_.annotation.name(authAnnotations))
    .whereNot(_.name(publicMethods))
    .map(m => {
      val file = escape(m.file.name.headOption.getOrElse("unknown"))
      val line = m.lineNumber.getOrElse(-1)
      val method = escape(m.name)
      s"""{"file":"$file","line":$line,"method":"$method","severity":"high","rule":"missing-authorization"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
