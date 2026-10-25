import SwiftUI
import CryptoKit
import CommonCrypto
import UIKit

@main
struct WebtronicsApp: App {
    var body: some Scene {
        WindowGroup {
            AuthenticatorView()
                .preferredColorScheme(.dark)
        }
    }
}

struct SeedRecord: Decodable {
    let version: Int
    let iterations: Int
    let salt: String
    let iv: String
    let ciphertext: String
}

struct Account: Decodable, Identifiable {
    private let storedID: String?
    let issuer: String?
    let account: String
    let secret: String
    let algorithm: String
    let digits: Int
    let period: Int

    var id: String { storedID ?? "\(issuer ?? "")|\(account)" }

    enum CodingKeys: String, CodingKey {
        case storedID = "id"
        case issuer, account, secret, algorithm, digits, period
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if let stringID = try? values.decode(String.self, forKey: .storedID) { storedID = stringID } else if let numericID = try? values.decode(Int.self, forKey: .storedID) { storedID = String(numericID) } else { storedID = nil }
        issuer = try values.decodeIfPresent(String.self, forKey: .issuer)
        account = try values.decode(String.self, forKey: .account)
        secret = try values.decode(String.self, forKey: .secret)
        algorithm = try values.decodeIfPresent(String.self, forKey: .algorithm) ?? "SHA1"
        digits = try values.decodeIfPresent(Int.self, forKey: .digits) ?? 6
        period = try values.decodeIfPresent(Int.self, forKey: .period) ?? 30
    }
}

struct OTPValue {
    let code: String
    let secondsRemaining: Int
}

enum AuthenticatorError: LocalizedError {
    case missingSeedFile, invalidSeedFile, decryptionFailed, invalidAccount, unsupportedAlgorithm

    var errorDescription: String? {
        switch self {
        case .missingSeedFile: return "인증 데이터 파일을 찾을 수 없습니다."
        case .invalidSeedFile: return "인증 데이터 형식이 올바르지 않습니다."
        case .decryptionFailed: return "비밀번호가 맞지 않습니다."
        case .invalidAccount: return "인증 계정 데이터를 읽을 수 없습니다."
        case .unsupportedAlgorithm: return "지원하지 않는 인증 알고리즘입니다."
        }
    }
}

enum WebtronicsCrypto {
    static func decryptAccounts(password: String) throws -> [Account] {
        guard let url = Bundle.main.url(forResource: "seeds.enc", withExtension: "json") else {
            throw AuthenticatorError.missingSeedFile
        }
        let record = try JSONDecoder().decode(SeedRecord.self, from: Data(contentsOf: url))
        guard record.version == 1, record.iterations > 0,
              let salt = Data(base64Encoded: record.salt),
              let nonce = Data(base64Encoded: record.iv),
              let encrypted = Data(base64Encoded: record.ciphertext) else {
            throw AuthenticatorError.invalidSeedFile
        }

        let passwordData = Data(password.utf8)
        var keyData = Data(count: 32)
        let keyLength = keyData.count
        let status = keyData.withUnsafeMutableBytes { keyBuffer in
            salt.withUnsafeBytes { saltBuffer in
                passwordData.withUnsafeBytes { passwordBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(record.iterations),
                        keyBuffer.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw AuthenticatorError.decryptionFailed }

        do {
            let symmetricKey = SymmetricKey(data: keyData)
            let combined = nonce + encrypted
            let box = try AES.GCM.SealedBox(combined: combined)
            let plaintext = try AES.GCM.open(box, using: symmetricKey)
            let payload = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any]
            guard let dictionaries = payload?["accounts"] as? [[String: Any]] else {
                throw AuthenticatorError.invalidSeedFile
            }
            let accountData = try JSONSerialization.data(withJSONObject: dictionaries)
            return try JSONDecoder().decode([Account].self, from: accountData)
        } catch let error as AuthenticatorError {
            throw error
        } catch {
            throw AuthenticatorError.decryptionFailed
        }
    }

    static func base32Bytes(_ raw: String) throws -> [UInt8] {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        let normalized = raw.uppercased().filter { !$0.isWhitespace && $0 != "=" && $0 != "-" }
        var buffer: UInt32 = 0
        var bits = 0
        var result: [UInt8] = []
        for character in normalized {
            guard let value = alphabet.firstIndex(of: character) else {
                throw AuthenticatorError.invalidAccount
            }
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                bits -= 8
                result.append(UInt8((buffer >> bits) & 0xff))
                buffer &= (1 << bits) - 1
            }
        }
        guard !result.isEmpty else { throw AuthenticatorError.invalidAccount }
        return result
    }

    static func totp(for account: Account, date: Date = Date()) throws -> OTPValue {
        guard account.period > 0, [6, 8].contains(account.digits) else {
            throw AuthenticatorError.invalidAccount
        }
        let secret = try base32Bytes(account.secret)
        let seconds = Int(date.timeIntervalSince1970)
        guard seconds >= 0 else { throw AuthenticatorError.invalidAccount }
        let counter = UInt64(seconds / account.period)
        var bigEndianCounter = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }

        let algorithm: CCHmacAlgorithm
        let digestLength: Int
        switch account.algorithm.uppercased() {
        case "SHA1": algorithm = CCHmacAlgorithm(kCCHmacAlgSHA1); digestLength = CC_SHA1_DIGEST_LENGTH
        case "SHA256": algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256); digestLength = CC_SHA256_DIGEST_LENGTH
        case "SHA512": algorithm = CCHmacAlgorithm(kCCHmacAlgSHA512); digestLength = CC_SHA512_DIGEST_LENGTH
        default: throw AuthenticatorError.unsupportedAlgorithm
        }

        var digest = Data(count: digestLength)
        secret.withUnsafeBytes { keyBuffer in
            counterData.withUnsafeBytes { messageBuffer in
                digest.withUnsafeMutableBytes { outputBuffer in
                    CCHmac(algorithm, keyBuffer.baseAddress, secret.count,
                           messageBuffer.baseAddress, counterData.count, outputBuffer.baseAddress)
                }
            }
        }

        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let modulus = UInt32(pow(10.0, Double(account.digits)))
        let code = String(format: "%0*u", account.digits, binary % modulus)
        let remaining = account.period - (seconds % account.period)
        return OTPValue(code: code, secondsRemaining: remaining)
    }
}

@MainActor
final class AuthenticatorStore: ObservableObject {
    @Published private(set) var accounts: [Account] = []
    @Published private(set) var values: [String: OTPValue] = [:]
    @Published var errorMessage = ""
    @Published private(set) var isUnlocked = false
    @Published var copiedAccountID: String?

    func unlock(password: String) {
        errorMessage = ""
        do {
            accounts = try WebtronicsCrypto.decryptAccounts(password: password)
            isUnlocked = true
            refresh()
        } catch {
            errorMessage = "비밀번호가 맞지 않거나 인증 데이터를 해독할 수 없습니다."
        }
    }

    func lock() {
        accounts = []
        values = [:]
        isUnlocked = false
        copiedAccountID = nil
    }

    func refresh() {
        guard isUnlocked else { return }
        var next: [String: OTPValue] = [:]
        for account in accounts {
            if let value = try? WebtronicsCrypto.totp(for: account) {
                next[account.id] = value
            }
        }
        values = next
    }

    func copy(_ account: Account) {
        guard let value = values[account.id] else { return }
        UIPasteboard.general.string = value.code
        copiedAccountID = account.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            if self.copiedAccountID == account.id { self.copiedAccountID = nil }
        }
    }
}

struct AuthenticatorView: View {
    @StateObject private var store = AuthenticatorStore()
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            Group {
                if store.isUnlocked {
                    accountList
                } else {
                    lockScreen
                }
            }
            .background(Color(red: 0.09, green: 0.09, blue: 0.10))
            .toolbar {
                if store.isUnlocked {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("잠금") { store.lock() }
                    }
                }
            }
            .navigationTitle("세미콜론 ;")
            .navigationBarTitleDisplayMode(.inline)
        }
        .tint(Color(red: 0.34, green: 0.61, blue: 0.84))
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                store.refresh()
            }
        }
    }

    private var lockScreen: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield")
                .font(.system(size: 48, weight: .light))
                .foregroundStyle(.blue)
            Text("Webtronics")
                .font(.largeTitle.bold())
            Text("// 코딩 동아리 전용 인증 코드 보관함")
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            SecureField("비밀번호", text: $password)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($passwordFocused)
                .submitLabel(.go)
                .onSubmit(submitUnlock)
                .padding(14)
                .background(Color.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
            Button(action: submitUnlock) {
                Label("잠금 해제", systemImage: "lock.open")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            if !store.errorMessage.isEmpty {
                Text(store.errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(maxWidth: 480)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var accountList: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                ForEach(store.accounts) { account in
                    if let value = store.values[account.id] {
                        Button { store.copy(account) } label: {
                            accountCard(account, value: value)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("\(account.issuer ?? "") \(account.account), 코드 \(value.code), 남은 시간 \(value.secondsRemaining)초. 눌러서 복사")
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: 620)
            .frame(maxWidth: .infinity)
        }
    }

    private func accountCard(_ account: Account, value: OTPValue) -> some View {
        let ending = value.secondsRemaining <= 5
        return VStack(alignment: .leading, spacing: 10) {
            Text(account.issuer.map { "\($0) (\(account.account))" } ?? account.account)
                .font(.caption.monospaced())
                .foregroundStyle(Color(red: 0.53, green: 0.72, blue: 0.48))
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(alignment: .center, spacing: 12) {
                Text(groupDigits(value.code))
                    .font(.system(size: 34, weight: .semibold, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(ending ? Color.orange : Color.white)
                    .minimumScaleFactor(0.7)
                    .lineLimit(1)
                Spacer(minLength: 4)
                VStack(spacing: 5) {
                    ZStack {
                        Circle().stroke(Color.white.opacity(0.12), lineWidth: 3)
                        Circle()
                            .trim(from: 0, to: CGFloat(value.secondsRemaining) / CGFloat(max(1, account.period)))
                            .stroke(ending ? Color.orange : Color.blue, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(value.secondsRemaining)")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .monospacedDigit()
                    }
                    .frame(width: 36, height: 36)
                    Text(store.copiedAccountID == account.id ? "복사됨" : "\(value.secondsRemaining)초")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(ending ? Color.orange : Color.secondary)
                }
            }
        }
        .padding(16)
        .background(Color(red: 0.145, green: 0.145, blue: 0.155), in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.white.opacity(0.08), lineWidth: 1))
        .contentShape(RoundedRectangle(cornerRadius: 14))
    }

    private func groupDigits(_ code: String) -> String {
        let half = (code.count + 1) / 2
        let split = code.index(code.startIndex, offsetBy: half)
        return String(code[..<split]) + " " + String(code[split...])
    }

    private func submitUnlock() {
        store.unlock(password: password)
        if store.isUnlocked {
            password = ""
            passwordFocused = false
        }
    }
}
