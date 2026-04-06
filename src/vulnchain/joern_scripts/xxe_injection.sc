// Joern CPG script: detect XML External Entity (XXE) injection
// Detects XML parsing without DTD/entity protection
// Supports: Java (DocumentBuilderFactory, SAXParserFactory, XMLReader),
//           C# (XmlDocument, XmlReader), Python (lxml, ElementTree)

@main def exec(cpgFile: String, outputFile: String): Unit = {
  importCpg(cpgFile)

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

  // XML parsing sinks vulnerable to XXE when DTD loading is not disabled
  val xmlParseSinks =
    "(parse|loadXML|load|parseString|fromstring|" +
    "newDocumentBuilder|newSAXParser|createXMLReader|" +
    "DocumentBuilder\\.parse|SAXParser\\.parse|" +
    "XmlDocument\\.Load|XmlDocument\\.LoadXml|" +
    "XmlReader\\.Create|XmlTextReader|" +
    "etree\\.parse|etree\\.fromstring|" +
    "lxml\\.etree\\.parse|lxml\\.etree\\.fromstring|" +
    "simplexml_load_string|simplexml_load_file).*"

  // User-controlled source parameters
  val sourcePattern =
    "(.*[Ii]nput|.*[Rr]equest|.*[Bb]ody|.*[Pp]aram|.*[Cc]ontent|" +
    ".*[Uu]pload|.*[Xx]ml|.*[Dd]ata|.*[Pp]ayload|.*[Rr]aw|" +
    ".*[Ss]tream|.*[Ff]ile|.*[Uu]rl|.*[Uu]ri).*"

  // Sanitizer: methods that disable DTD/entity processing
  val sanitizerPattern =
    "(setFeature|setExpandEntityReferences|setEntityResolver|" +
    "ProhibitDtd|DtdProcessing\\.Prohibit|" +
    "disableEntityLoader|FEATURE_SECURE_PROCESSING).*"

  val results = cpg.call
    .name(xmlParseSinks)
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
      s"""{"file":"$file","line":$line,"method":"$method","enclosing_method":"$enclosing","severity":"high","rule":"xxe-injection"}"""
    })
    .l

  val json = "[" + results.mkString(",") + "]"
  java.nio.file.Files.write(
    java.nio.file.Paths.get(outputFile),
    json.getBytes("UTF-8")
  )
}
