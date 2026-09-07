import XCTest
@testable import PEMCore

/// Integration tests. Fixtures are generated with the system `openssl` (LibreSSL) so the
/// in-process parser, key matcher and exporter are checked against an independent implementation.
final class PEMCoreTests: XCTestCase {
    var folder: URL!

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("ssl2pem-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "30",
                    "-subj", "/CN=Test CA/O=PEMCore Tests", "-config", config("ca.cnf", """
        [req]
        distinguished_name = dn
        x509_extensions = ca
        [dn]
        [ca]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign
        """))
        try openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=example.test/O=Example")
        try openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                    "-out", "server.crt", "-days", "10", "-extfile", config("server.cnf", """
        basicConstraints = CA:FALSE
        subjectAltName = DNS:example.test,DNS:www.example.test,IP:127.0.0.1
        extendedKeyUsage = serverAuth
        """))
    }

    override func tearDownWithError() throws {
        if let folder { try? FileManager.default.removeItem(at: folder) }
    }

    // MARK: Parsing & classification

    func testInspectAndAutoClassification() throws {
        let cert = try PEMImporter.read(url("server.crt"))
        XCTAssertEqual(cert.role, .certificate)
        let info = try CertificateInfo.parse(der: try XCTUnwrap(cert.blocks.first).der)
        XCTAssertEqual(info.commonName, "example.test")
        XCTAssertEqual(info.subjectAltNames, ["example.test", "www.example.test", "127.0.0.1"])
        XCTAssertEqual(info.coveredNames, ["example.test", "www.example.test", "127.0.0.1"])
        XCTAssertTrue(info.issuer.contains("Test CA"))
        XCTAssertEqual(info.keyDescription, "RSA 2048-bit")
        XCTAssertEqual(info.signatureAlgorithm, "SHA-256 with RSA")
        let notBefore = try XCTUnwrap(info.notBefore), notAfter = try XCTUnwrap(info.notAfter)
        XCTAssertTrue(notAfter > notBefore)
        XCTAssertEqual(info.daysRemaining, 9)
        XCTAssertFalse(info.isExpired)
        XCTAssertFalse(info.isSelfSigned)
        XCTAssertEqual(info.sha256Fingerprint.split(separator: ":").count, 32)
        XCTAssertEqual(info.suggestedFileName, "example.test.pem")
        XCTAssertTrue(info.allFields.contains { $0.section == "Subject Alternative Name" || $0.value.contains("www.example.test") })

        // A lone CA certificate is recognised as chain material even without a helpful file name.
        try FileManager.default.copyItem(at: url("ca.crt"), to: url("something.pem"))
        XCTAssertEqual(try PEMImporter.read(url("something.pem")).role, .chain)
        XCTAssertEqual(try PEMImporter.read(url("ca.crt")).role, .chain)
        XCTAssertEqual(try PEMImporter.read(url("server.key")).role, .key)
        XCTAssertTrue(try PEMImporter.read(url("ca.crt")).blocks.allSatisfy { PEMImporter.isCertificateAuthority($0.der) })
        XCTAssertFalse(PEMImporter.isCertificateAuthority(try XCTUnwrap(cert.blocks.first).der))
    }

    func testFingerprintMatchesOpenSSL() throws {
        let cert = try PEMImporter.read(url("server.crt"))
        let info = try CertificateInfo.parse(der: try XCTUnwrap(cert.blocks.first).der)
        let expected = try opensslOutput("x509", "-in", "server.crt", "-noout", "-fingerprint", "-sha256")
        XCTAssertTrue(expected.uppercased().contains(info.sha256Fingerprint), "\(expected) should contain \(info.sha256Fingerprint)")
    }

    func testDERCertificate() throws {
        try openssl("x509", "-in", "server.crt", "-outform", "DER", "-out", "certificate.cer")
        let file = try PEMImporter.read(url("certificate.cer"))
        XCTAssertEqual(file.role, .certificate)
        XCTAssertEqual(try CertificateInfo.parse(der: try XCTUnwrap(file.blocks.first).der).commonName, "example.test")
        XCTAssertTrue(file.blocks[0].armored.hasPrefix("-----BEGIN CERTIFICATE-----"))
    }

    func testMalformedAndMixedInputsRejected() throws {
        try Data("not a certificate".utf8).write(to: url("invalid.crt"))
        XCTAssertThrowsError(try PEMImporter.read(url("invalid.crt")))
        var lines = String(decoding: try Data(contentsOf: url("server.crt")), as: UTF8.self).split(separator: "\n")
        lines.remove(at: lines.count / 2)   // drop a line of base64 from the middle
        try Data(lines.joined(separator: "\n").utf8).write(to: url("corrupt.crt"))
        XCTAssertThrowsError(try PEMImporter.read(url("corrupt.crt")))

        let mixed = try Data(contentsOf: url("server.key")) + Data(contentsOf: url("server.crt"))
        try mixed.write(to: url("mixed.pem"))
        XCTAssertThrowsError(try PEMImporter.read(url("mixed.pem")))              // ambiguous when auto-classifying
        XCTAssertEqual(try PEMImporter.read(url("mixed.pem"), as: .key).role, .key) // fine when the slot is explicit
        XCTAssertNotNil(try PEMImporter.read(url("mixed.pem"), as: .certificate).warning)

        XCTAssertThrowsError(try PEMImporter.read(url("server.key"), as: .certificate))
        XCTAssertThrowsError(try PEMImporter.read(url("server.crt"), as: .key))
        XCTAssertThrowsError(try PEMImporter.read(folder))
    }

    func testInputLimitsAndPassphraseNewlines() throws {
        try Data(repeating: 65, count: PEMImporter.maximumInputSize + 1).write(to: url("oversized.pem"))
        XCTAssertThrowsError(try PEMImporter.read(url("oversized.pem")))
        try openssl("pkey", "-in", "server.key", "-aes-256-cbc", "-passout", "pass:fixture-only", "-out", "encrypted.key")
        XCTAssertThrowsError(try export(key: "encrypted.key", passphrase: "one\ntwo"))
    }

    // MARK: Export content

    func testMatchingRSAExportAndPrivatePermissions() throws {
        let result = try export()
        XCTAssertTrue(result.containsPrivateKey)
        let text = result.pem
        XCTAssertTrue(text.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertEqual(text.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1, 2)
        XCTAssertTrue(text.hasSuffix("-----END CERTIFICATE-----\n"))

        let destination = url("output.pem")
        try PEMWriter.save(result.data, to: destination, containsPrivateKey: true)
        XCTAssertEqual(try Data(contentsOf: destination), result.data)
        XCTAssertEqual(permissions(of: destination), 0o600)

        // The independent implementation can read both the certificate and the key from the output.
        try openssl("x509", "-in", destination.path, "-noout")
        try openssl("pkey", "-in", destination.path, "-noout")
        try openssl("verify", "-CAfile", "ca.crt", destination.path)

        // Overwriting works and keeps the permissions.
        try PEMWriter.save(result.data, to: destination, containsPrivateKey: true)
        XCTAssertEqual(permissions(of: destination), 0o600)
    }

    func testKeyFreeExportIsWorldReadable() throws {
        let result = try PEMExporter.export(key: [], certificate: read("server.crt").blocks,
                                            ca: read("ca.crt").blocks, order: .certCA)
        XCTAssertFalse(result.containsPrivateKey)
        let destination = url("fullchain.pem")
        try PEMWriter.save(result.data, to: destination, containsPrivateKey: false)
        XCTAssertEqual(permissions(of: destination), 0o644)
    }

    func testHAProxyFormatPreservesExactContents() throws {
        let key = try read("server.key"), cert = try read("server.crt"), chain = try read("ca.crt")
        let haproxy = try PEMExporter.export(key: key.blocks, certificate: cert.blocks, ca: chain.blocks, order: .certCAKey)
        XCTAssertEqual(haproxy.pem, cert.blocks[0].armored + "\n" + chain.blocks[0].armored + "\n" + key.blocks[0].armored + "\n")
        try haproxy.data.write(to: url("alternate.pem"))
        try openssl("x509", "-in", "alternate.pem", "-noout")
        try openssl("pkey", "-in", "alternate.pem", "-noout")

        let combined = try PEMExporter.export(key: key.blocks, certificate: cert.blocks, ca: chain.blocks, order: .keyCertCA)
        XCTAssertEqual(combined.pem, key.blocks[0].armored + "\n" + cert.blocks[0].armored + "\n" + chain.blocks[0].armored + "\n")

        let certKeyCA = try PEMExporter.export(key: key.blocks, certificate: cert.blocks, ca: chain.blocks, order: .certKeyCA)
        XCTAssertEqual(certKeyCA.pem, cert.blocks[0].armored + "\n" + key.blocks[0].armored + "\n" + chain.blocks[0].armored + "\n")
    }

    func testArmorIsNormalisedButBase64IsUntouched() throws {
        // CRLF line endings and surrounding `openssl x509 -text` noise are stripped; the body is byte-identical.
        let original = String(decoding: try Data(contentsOf: url("server.crt")), as: UTF8.self)
        let noisy = "Certificate:\n    Data:\n        Version: 3\n" + original.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n"
        try Data(noisy.utf8).write(to: url("noisy.crt"))
        let clean = try read("server.crt"), dirty = try read("noisy.crt")
        XCTAssertEqual(clean.blocks, dirty.blocks)
        XCTAssertFalse(dirty.blocks[0].armored.contains("\r"))
    }

    func testLeafExportNeedsNoKeyAndExcludesAllOtherMaterial() throws {
        let cert = try read("server.crt"), chain = try read("ca.crt")
        let withoutKey = try PEMExporter.export(key: [], certificate: cert.blocks, ca: chain.blocks, order: .certOnly)
        XCTAssertEqual(withoutKey.pem, cert.blocks[0].armored + "\n")
        // An unrelated key is irrelevant to certificate-only exports and must not block them.
        let withWrongKey = try PEMExporter.export(key: read("ca.key").blocks, certificate: cert.blocks, ca: chain.blocks,
                                                  passphrase: "irrelevant", order: .certOnly)
        XCTAssertEqual(withWrongKey.pem, withoutKey.pem)
        // Leaf-only stays leaf-only even when the certificate slot holds a fullchain file.
        let fullchain = try Data(contentsOf: url("server.crt")) + Data(contentsOf: url("ca.crt"))
        try fullchain.write(to: url("fullchain.pem"))
        let leafOnly = try PEMExporter.export(key: [], certificate: read("fullchain.pem").blocks, ca: [], order: .certOnly)
        XCTAssertEqual(leafOnly.pem, withoutKey.pem)
    }

    func testFullChainExportHasNoPrivateKeyAndKeepsLeafFirst() throws {
        let cert = try read("server.crt"), chain = try read("ca.crt")
        let result = try PEMExporter.export(key: [], certificate: cert.blocks, ca: chain.blocks, order: .certCA)
        XCTAssertEqual(result.pem, cert.blocks[0].armored + "\n" + chain.blocks[0].armored + "\n")
        XCTAssertFalse(result.pem.contains("PRIVATE KEY"))
        try result.data.write(to: url("fullchain.pem"))
        try openssl("x509", "-in", "fullchain.pem", "-noout")
        let noChain = try PEMExporter.export(key: [], certificate: cert.blocks, ca: [], order: .certCA)
        XCTAssertEqual(noChain.pem, cert.blocks[0].armored + "\n")
        XCTAssertTrue(noChain.warnings.contains { $0.contains("No CA bundle") })
    }

    func testChainInsideCertificateFileIsUsedAndDeduplicated() throws {
        let fullchain = try Data(contentsOf: url("server.crt")) + Data(contentsOf: url("ca.crt"))
        try fullchain.write(to: url("fullchain.pem"))
        // Certificate slot already carries the chain; the CA slot repeats it. Output has each cert once.
        let result = try PEMExporter.export(key: read("server.key").blocks, certificate: read("fullchain.pem", as: .certificate).blocks,
                                            ca: read("ca.crt").blocks, order: .keyCertCA)
        XCTAssertEqual(result.pem.components(separatedBy: "BEGIN CERTIFICATE").count - 1, 2)
        XCTAssertTrue(result.warnings.contains { $0.contains("duplicate") })
    }

    // MARK: Export safeguards

    func testFormatsWithKeysRequireAKey() throws {
        let cert = try read("server.crt")
        for order in PEMOrder.allCases where order.includesKey {
            XCTAssertThrowsError(try PEMExporter.export(key: [], certificate: cert.blocks, ca: [], order: order)) {
                XCTAssertTrue($0.localizedDescription.contains("requires a private key"), "\(order): \($0)")
            }
        }
        for order in PEMOrder.allCases where !order.includesKey {
            XCTAssertNoThrow(try PEMExporter.export(key: [], certificate: cert.blocks, ca: [], order: order))
        }
    }

    func testWrongKeyIsRejected() throws {
        XCTAssertThrowsError(try export(key: "ca.key")) {
            XCTAssertTrue($0.localizedDescription.contains("does not match"), "\($0)")
        }
        let info = PrivateKeyInspector.inspect(blocks: try read("ca.key").blocks,
                                               certificate: SecCertificateCreateWithData(nil, try read("server.crt").blocks[0].der as CFData))
        XCTAssertEqual(info.match, .mismatch)
    }

    func testMissingCertificateIsRejected() throws {
        XCTAssertThrowsError(try PEMExporter.export(key: read("server.key").blocks, certificate: [], ca: [], order: .keyCertCA))
    }

    func testHAProxyRejectsMismatchedKeyAndRemovesDuplicates() throws {
        let caData = try Data(contentsOf: url("ca.crt"))
        try (caData + caData).write(to: url("duplicate.crt"))
        let key = try read("server.key"), cert = try read("server.crt"), chain = try read("duplicate.crt")
        XCTAssertEqual(chain.certificateCount, 2)
        let result = try PEMExporter.export(key: key.blocks, certificate: cert.blocks, ca: chain.blocks, order: .certCAKey)
        XCTAssertEqual(result.pem, cert.blocks[0].armored + "\n" + chain.blocks[0].armored + "\n" + key.blocks[0].armored + "\n")
        XCTAssertThrowsError(try PEMExporter.export(key: read("ca.key").blocks, certificate: cert.blocks, ca: chain.blocks, order: .certCAKey))
    }

    func testDuplicateChainCertificatesRemoved() throws {
        let ca = try Data(contentsOf: url("ca.crt"))
        try (ca + ca).write(to: url("duplicate.crt"))
        let result = try PEMExporter.export(key: read("server.key").blocks, certificate: read("server.crt").blocks,
                                            ca: read("duplicate.crt").blocks, order: .keyCertCA)
        XCTAssertEqual(result.pem.components(separatedBy: "BEGIN CERTIFICATE").count - 1, 2)
    }

    // MARK: Encrypted keys

    func testEncryptedKeyPreservedAndWrongPasswordRejected() throws {
        try openssl("pkey", "-in", "server.key", "-aes-256-cbc", "-passout", "pass:fixture-only", "-out", "encrypted.key")
        let key = try read("encrypted.key")
        XCTAssertEqual(key.role, .key)
        XCTAssertTrue(key.isEncryptedKey)

        XCTAssertThrowsError(try export(key: "encrypted.key")) { XCTAssertTrue($0.localizedDescription.contains("passphrase")) }
        XCTAssertThrowsError(try export(key: "encrypted.key", passphrase: "wrong")) { XCTAssertTrue($0.localizedDescription.contains("passphrase")) }

        let exported = try export(key: "encrypted.key", passphrase: "fixture-only")
        XCTAssertTrue(exported.pem.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        try exported.data.write(to: url("exported.pem"))
        try openssl("pkey", "-in", "exported.pem", "-noout", "-passin", "pass:fixture-only")
    }

    func testEncryptedKeyWithSHA1PRFAndLegacyPEMFormat() throws {
        // PBES2 with 3DES (and, on LibreSSL, the PBKDF2 default PRF HMAC-SHA1).
        try openssl("pkcs8", "-topk8", "-in", "server.key", "-v2", "des3",
                    "-passout", "pass:legacy-ish", "-out", "des3.key")
        XCTAssertNoThrow(try export(key: "des3.key", passphrase: "legacy-ish"))

        // Legacy OpenSSL PEM encryption (Proc-Type / DEK-Info headers).
        try openssl("rsa", "-in", "server.key", "-aes256", "-passout", "pass:old-style", "-out", "legacy.key")
        let legacy = try read("legacy.key")
        XCTAssertTrue(legacy.isEncryptedKey)
        XCTAssertEqual(legacy.blocks[0].type, "RSA PRIVATE KEY")
        XCTAssertNotNil(legacy.blocks[0].headers["DEK-Info"])
        XCTAssertThrowsError(try export(key: "legacy.key", passphrase: "nope"))
        let exported = try export(key: "legacy.key", passphrase: "old-style")
        XCTAssertTrue(exported.pem.contains("Proc-Type: 4,ENCRYPTED"))
        try exported.data.write(to: url("legacy-exported.pem"))
        try openssl("rsa", "-in", "legacy-exported.pem", "-noout", "-passin", "pass:old-style")
    }

    func testHAProxyWithoutChainAndWithEncryptedKey() throws {
        try openssl("pkey", "-in", "server.key", "-aes-256-cbc", "-passout", "pass:fixture-only", "-out", "encrypted.key")
        let key = try read("encrypted.key"), cert = try read("server.crt")
        let result = try PEMExporter.export(key: key.blocks, certificate: cert.blocks, ca: [], passphrase: "fixture-only", order: .certCAKey)
        XCTAssertEqual(result.pem, cert.blocks[0].armored + "\n" + key.blocks[0].armored + "\n")
        XCTAssertTrue(result.pem.contains("BEGIN ENCRYPTED PRIVATE KEY"))
    }

    // MARK: Key types

    func testECKeyAndCertificateMatch() throws {
        try openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ec.key")
        try openssl("req", "-new", "-x509", "-key", "ec.key", "-out", "ec.crt", "-days", "10", "-subj", "/CN=ec.example.test")
        let result = try PEMExporter.export(key: read("ec.key").blocks, certificate: read("ec.crt", as: .certificate).blocks, ca: [], order: .keyCertCA)
        XCTAssertTrue(result.pem.contains("BEGIN EC PRIVATE KEY"))
        let info = try CertificateInfo.parse(der: try read("ec.crt", as: .certificate).blocks[0].der)
        XCTAssertEqual(info.keyDescription, "ECDSA 256-bit")
        XCTAssertTrue(info.isSelfSigned)

        // Same key as PKCS#8, and the RSA key must not match the EC certificate.
        try openssl("pkcs8", "-topk8", "-nocrypt", "-in", "ec.key", "-out", "ec-pkcs8.key")
        XCTAssertNoThrow(try PEMExporter.export(key: read("ec-pkcs8.key").blocks, certificate: read("ec.crt", as: .certificate).blocks, ca: [], order: .keyCertCA))
        XCTAssertThrowsError(try PEMExporter.export(key: read("server.key").blocks, certificate: read("ec.crt", as: .certificate).blocks, ca: [], order: .keyCertCA))
    }

    func testPKCS1RSAKey() throws {
        try openssl("rsa", "-in", "server.key", "-out", "pkcs1.key")
        XCTAssertEqual(try read("pkcs1.key").blocks[0].type, "RSA PRIVATE KEY")
        XCTAssertNoThrow(try export(key: "pkcs1.key"))
    }

    // MARK: Chain verification

    func testChainVerificationAgainstPrivateRoot() throws {
        let leaf = SecCertificateCreateWithData(nil, try read("server.crt").blocks[0].der as CFData)!
        let root = SecCertificateCreateWithData(nil, try read("ca.crt").blocks[0].der as CFData)!
        let withRoot = ChainVerifier.verify(leaf: leaf, bundle: [root])
        XCTAssertEqual(withRoot.status, .privateRoot)
        XCTAssertEqual(withRoot.chain.count, 2)

        let alone = ChainVerifier.verify(leaf: leaf, bundle: [])
        XCTAssertEqual(alone.status, .invalid)

        let ecRoot = try { () -> SecCertificate in
            try openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "other.key")
            try openssl("req", "-new", "-x509", "-key", "other.key", "-out", "other.crt", "-days", "10", "-subj", "/CN=Unrelated CA")
            return SecCertificateCreateWithData(nil, try read("other.crt", as: .chain).blocks[0].der as CFData)!
        }()
        XCTAssertEqual(ChainVerifier.verify(leaf: leaf, bundle: [ecRoot]).status, .invalid)
    }

    // MARK: File writing

    func testExportReplacesSymlinkWithoutChangingItsTarget() throws {
        let original = url("original.txt")
        try Data("leave intact".utf8).write(to: original)
        let link = url("link.pem")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: original)
        try PEMWriter.save(try export().data, to: link, containsPrivateKey: true)
        XCTAssertEqual(try String(contentsOf: original), "leave intact")
        XCTAssertFalse(try link.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink ?? true)
        XCTAssertEqual(permissions(of: link), 0o600)
    }

    func testFailedSaveLeavesNoStagingFile() throws {
        let missingDir = url("does-not-exist").appendingPathComponent("out.pem")
        XCTAssertThrowsError(try PEMWriter.save(Data("x".utf8), to: missingDir, containsPrivateKey: true))
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { $0.hasPrefix(".ssl2pem-") }
        XCTAssertTrue(leftovers.isEmpty)
    }

    // MARK: Helpers

    private func url(_ name: String) -> URL { folder.appendingPathComponent(name) }

    private func read(_ name: String, as role: PEMRole? = nil) throws -> ImportedFile {
        try PEMImporter.read(url(name), as: role)
    }

    private func export(key: String = "server.key", passphrase: String = "", order: PEMOrder = .keyCertCA) throws -> ExportResult {
        try PEMExporter.export(key: read(key).blocks, certificate: read("server.crt").blocks, ca: read("ca.crt").blocks,
                               passphrase: passphrase, order: order)
    }

    private func permissions(of file: URL) -> Int? {
        (try? FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue
    }

    private func config(_ name: String, _ text: String) throws -> String {
        try text.write(to: url(name), atomically: true, encoding: .utf8)
        return url(name).path
    }

    private func openssl(_ arguments: String...) throws {
        _ = try opensslOutput(arguments)
    }

    private func opensslOutput(_ arguments: String...) throws -> String {
        try opensslOutput(arguments)
    }

    private func opensslOutput(_ arguments: [String]) throws -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        task.arguments = arguments
        task.currentDirectoryURL = folder
        let out = Pipe()
        task.standardOutput = out
        task.standardError = FileHandle.nullDevice
        try task.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw PEMError("openssl \(arguments.joined(separator: " ")) failed") }
        return String(decoding: data, as: UTF8.self)
    }
}
