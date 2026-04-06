// Joern CPG script: detect LDAP injection via taint analysis
// Tracks user-controlled data flowing into LDAP search/query operations
// Supports: Java (DirContext, LdapContext), C# (DirectorySearcher),
//           Python (python-ldap), PHP (ldap_search)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // LDAP operation sinks
  val sinkPattern =
    "(search|search_s|search_st|search_ext|search_ext_s|" +
    "DirContext\\.search|LdapContext\\.search|" +
    "DirectorySearcher|SearchRequest|" +
    "ldap_search|ldap_search_s|ldap_read|" +
    "NamingEnumeration|getAttributes|" +
    "FindAll|FindOne).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Uu]ser(?:[Nn]ame)?|.*[Ll]ogin|.*[Uu]id|.*[Ss]earch|" +
    ".*[Ff]ilter|.*[Qq]uery|.*[Ii]nput|.*[Pp]aram|.*[Rr]equest|" +
    ".*[Ee]mail|.*[Nn]ame|.*[Vv]alue).*"

  // Sanitizers — proper LDAP escaping
  val sanitizerPattern =
    "(escapeDN|escapeFilter|ldapEscape|escape_dn_chars|" +
    "escape_filter_chars|LdapEncoder|FilterEncoder).*"

  val results = cpg.call
    .name(sinkPattern)
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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"ldap-injection"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
