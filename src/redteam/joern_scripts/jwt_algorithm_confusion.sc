// Joern CPG script: detect JWT Algorithm Confusion attacks
// Traces the algorithm value from the JWT header back into the decode/verify call.
// When the algorithm is taken from the token itself (not hardcoded server-side),
// an attacker can switch RS256→HS256 and forge tokens signed with the public key.
// References: CVE-2022-21449 (Psychic Signatures), PortSwigger JWT labs,
//             RFC 8725 "JSON Web Token Best Current Practices"

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // JWT decode/verify sinks (Python: PyJWT, authlib; Node: jsonwebtoken; Java: jjwt, nimbus-jose)
  val jwtSinks =
    "(decode|verify|parse|parseSignedClaims|parseClaimsJws|" +
    "JwtParser|JWSVerifier|verify_compact_serialization|" +
    "JsonWebToken|jwt\\.verify|jwt\\.decode).*"

  // Algorithm extraction from token header — the dangerous pattern
  // Attacker controls token, therefore controls the 'alg' field
  val algorithmSources =
    "(getHeader|header|alg|algorithm|" +
    "getClaims|getAlgorithm|getAlgorithmFamily|" +
    "Base64\\.decode|base64url\\.decode|" +
    "split|getPayload|extractHeader).*"

  // Find JWT verify calls where the algorithm argument is derived from request input
  // (token is typically passed as Authorization header or body parameter)
  val tokenSources =
    "(getHeader|getParameter|getBody|" +
    "req\\.headers|req\\.body|request\\.headers|" +
    "Authorization|Bearer).*"

  // Primary detection: decode/verify called with user-supplied token AND
  // algorithm not hardcoded (algorithm comes from decoded header fields)
  val algorithmFromToken = cpg.call
    .name(jwtSinks)
    .where(
      _.argument.reachableBy(
        cpg.call.name(algorithmSources)
          .where(
            _.argument.reachableBy(
              cpg.call.name(tokenSources)
            )
          )
      )
    )
    .map(c => {
      val file      = escape(c.file.name.headOption.getOrElse("unknown"))
      val line      = c.lineNumber.getOrElse(-1)
      val method    = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"critical","rule":"jwt-algorithm-confusion","source":"token-header"}"""
    })
    .l

  // Secondary detection: algorithms=None / verify=False / options with no verify
  // (Insecure JWT decode with signature verification disabled)
  val noVerifyResults = cpg.call
    .name(jwtSinks)
    .where(
      _.argument.code(".*[Nn]one.*|.*[Vv]erify.*[Ff]alse.*|.*algorithms.*=.*\\[\\].*")
    )
    .map(c => {
      val file      = escape(c.file.name.headOption.getOrElse("unknown"))
      val line      = c.lineNumber.getOrElse(-1)
      val method    = escape(c.name)
      val enclosing = escape(c.method.name)
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"critical","rule":"jwt-no-verification","source":"decode-options"}"""
    })
    .l

  val allResults = (algorithmFromToken ++ noVerifyResults).distinct
  val json = "[" + allResults.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
