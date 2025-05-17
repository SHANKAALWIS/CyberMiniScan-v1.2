//Author:Shanka Alwis
//Date 15.5.2025
//Cyber Mini Scan App for Programming Languages and Paradigms - CSP3341 

import scala.io.Source
import scala.util.matching.Regex
import java.io.{File, PrintWriter}

// Case classes to hold scan results
case class PasswordIssue(line: Int, content: String)
case class FileExtensionIssue(line: Int, content: String)
case class UrlIssue(line: Int, content: String)

case class ScanResult(
  weakPasswords: List[PasswordIssue],
  suspiciousExtensions: List[FileExtensionIssue],
  dangerousUrls: List[UrlIssue]
)

// Object to encapsulate file reading
object InputReader {
  def readFile(filePath: String): List[String] = {
    Source.fromFile(filePath).getLines().toList
  }

  def readText(input: String): List[String] = {
    input.split("\n").toList
  }
}

// Scanner object containing logic
object Scanner {
  val weakPasswordPatterns: List[Regex] = List(
    "(?i)password".r,
    "123456".r,
    "qwerty".r,
    "letmein".r,
    "admin".r
  )

  val dangerousExtensions: List[String] = List(".exe", ".vbs", ".bat", ".scr", ".js", ".jar", ".ps1")

  val urlPattern: Regex = """https?://[\w\-._~:/?#\[\]@!$&'()*+,;=.]+""".r
  val suspiciousTlds: List[String] = List(".xyz", ".tk", ".ru", ".top")

  def scan(lines: List[String]): ScanResult = {
    val passwordIssues = lines.zipWithIndex.flatMap { case (line, idx) =>
      weakPasswordPatterns.collect {
        case pattern if pattern.findFirstIn(line).isDefined => PasswordIssue(idx + 1, line)
      }
    }

    val extensionIssues = lines.zipWithIndex.filter { case (line, _) =>
      dangerousExtensions.exists(ext => line.contains(ext))
    }.map { case (line, idx) => FileExtensionIssue(idx + 1, line) }

    val urlIssues = lines.zipWithIndex.flatMap { case (line, idx) =>
      urlPattern.findAllIn(line).flatMap { url =>
        suspiciousTlds.find(tld => url.endsWith(tld)).map(_ => UrlIssue(idx + 1, url))
      }
    }

    ScanResult(passwordIssues, extensionIssues, urlIssues)
  }
}

// Reporter for displaying and exporting results
object Reporter {
  def report(result: ScanResult): Unit = {
    println("=== Weak Passwords Detected ===")
    result.weakPasswords.foreach(p => println(s"Line ${p.line}: ${p.content}"))

    println("\n=== Suspicious File Extensions ===")
    result.suspiciousExtensions.foreach(f => println(s"Line ${f.line}: ${f.content}"))

    println("\n=== Dangerous URLs ===")
    result.dangerousUrls.foreach(u => println(s"Line ${u.line}: ${u.content}"))
  }

  def exportToJson(result: ScanResult, path: String): Unit = {
    val json =
      s"""{
         |  "weakPasswords": [${result.weakPasswords.map(p => s"""{"line": ${p.line}, "content": "${p.content}"}""").mkString(",")}],
         |  "suspiciousExtensions": [${result.suspiciousExtensions.map(f => s"""{"line": ${f.line}, "content": "${f.content}"}""").mkString(",")}],
         |  "dangerousUrls": [${result.dangerousUrls.map(u => s"""{"line": ${u.line}, "content": "${u.content}"}""").mkString(",")}]
         |}""".stripMargin

    val writer = new PrintWriter(new File(path))
    writer.write(json)
    writer.close()
  }

  def exportToCsv(result: ScanResult, path: String): Unit = {
    val writer = new PrintWriter(new File(path))
    writer.println("Issue Type,Line,Content")
    result.weakPasswords.foreach(p => writer.println(s"Weak Password,${p.line},\"${p.content}\""))
    result.suspiciousExtensions.foreach(f => writer.println(s"Suspicious Extension,${f.line},\"${f.content}\""))
    result.dangerousUrls.foreach(u => writer.println(s"Dangerous URL,${u.line},\"${u.content}\""))
    writer.close()
  }
}

// Main App
object CyberMiniScanApp extends App {
  val filePath = args.headOption.getOrElse("sample.txt")
  val lines = InputReader.readFile(filePath)
  val result = Scanner.scan(lines)
  Reporter.report(result)
  Reporter.exportToJson(result, "scan_output.json")
  Reporter.exportToCsv(result, "scan_output.csv")
}
