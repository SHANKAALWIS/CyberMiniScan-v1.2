import org.scalatest.funsuite.AnyFunSuite

class CyberMiniScanTests extends AnyFunSuite {
  test("Detects weak passwords") {
    val lines = List("My password is 123456")
    val result = Scanner.scan(lines)
    assert(result.weakPasswords.nonEmpty)
  }

  test("Detects dangerous URLs") {
    val lines = List("Visit http://evilsite.tk now!")
    val result = Scanner.scan(lines)
    assert(result.dangerousUrls.nonEmpty)
  }

  test("Detects suspicious extensions") {
    val lines = List("Click me: file.exe")
    val result = Scanner.scan(lines)
    assert(result.suspiciousExtensions.nonEmpty)
  }
}
