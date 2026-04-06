// Joern CPG script: detect insecure deserialization
// Tracks user-controlled data flowing into deserialization sinks
// Supports: Java (ObjectInputStream, XMLDecoder, XStream), C# (BinaryFormatter)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // Deserialization sinks — can execute arbitrary code on untrusted input
  val sinkPattern =
    "(readObject|readUnshared|readResolve|readExternal|" +
    "fromXML|fromJson|deserialize|Deserialize|" +
    "BinaryFormatter|SoapFormatter|LosFormatter|" +
    "XmlSerializer|DataContractSerializer|" +
    "ObjectInputStream|XMLDecoder|XStream|" +
    "JsonConvert\\.DeserializeObject|" +
    "pickle\\.loads|pickle\\.load|" +
    "Marshal\\.load|Marshal\\.restore|" +
    "yaml\\.load|yaml\\.unsafe_load|" +
    "unserialize|unpack).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Ii]nput|.*[Rr]equest|.*[Pp]aram|.*[Bb]ody|.*[Pp]ayload|" +
    ".*[Ss]tream|.*[Dd]ata|.*[Cc]ontent|.*[Uu]pload|" +
    ".*[Bb]uffer|.*[Bb]ytes|.*[Rr]aw|.*[Uu]ser.*).*"

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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"critical","rule":"insecure-deserialization"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
