// Joern CPG script: detect SQL injection via taint analysis
// Supports: Java, C#, PHP, Python, JavaScript

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // SQL execution sinks — covers .NET, JDBC, PHP, Python DB-API, JS
  val sinkPattern =
    "(Execute|ExecuteScalar|ExecuteReader|ExecuteNonQuery|" +
    "Query|FromSqlRaw|FromSqlInterpolated|" +
    "mysql_query|mysqli_query|pg_query|sqlite_query|" +
    "cursor\\.execute|connection\\.execute|" +
    "db\\.run|db\\.query|knex\\.raw|sequelize\\.query).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Ii]nput|.*[Rr]equest|.*[Pp]aram|.*[Qq]uery|.*[Bb]ody|" +
    ".*[Uu]ser.*|.*[Ss]earch|.*[Ff]ilter|.*[Ii]d|.*[Nn]ame).*"

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
      s"""{"file":"$file","line":$line,"method":"$method","severity":"critical","rule":"tainted-sql-injection"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
