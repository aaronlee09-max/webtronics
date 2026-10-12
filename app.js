import { base32ToBytes, generateTotp, parseOtpAuthUri } from "./totp.js";

const STORAGE_KEY = "webtronics-auth-vault-v1";
const VAULT_VERSION = 1;
const PBKDF2_ITERATIONS = 310_000;
const DAILY_GATE_SESSION_KEY = "webtronics-demo-gate-day";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (selector) => document.querySelector(selector);

const elements = {
  dateGate: $("#date-gate"),
  dailyDemoPassword: $("#daily-demo-password"),
  dailyGateError: $("#daily-gate-error"),
  setupPanel: $("#setup-panel"),
  unlockPanel: $("#unlock-panel"),
  vaultPanel: $("#vault-panel"),
  accountList: $("#account-list"),
  emptyState: $("#empty-state"),
  setupPassword: $("#setup-password"),
  setupPasswordConfirm: $("#setup-password-confirm"),
  unlockPassword: $("#unlock-password"),
  addDialog: $("#add-dialog"),
  addUri: $("#add-uri"),
  issuer: $("#issuer"),
  account: $("#account"),
  secret: $("#secret"),
  algorithm: $("#algorithm"),
  digits: $("#digits"),
  period: $("#period"),
  video: $("#qr-video"),
  scannerPanel: $("#scanner-panel"),
  backupImport: $("#backup-import"),
  toast: $("#toast"),
};

let accounts = [];
let vaultKey = null;
let vaultRecord = null;
let refreshTimer = null;
let autoLockTimer = null;
let dailyGateTimer = null;
let toastTimer = null;
let lastActivity = Date.now();
let qrStream = null;
let qrTimer = null;
let qrBusy = false;
let renderGeneration = 0;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function showToast(message, kind = "info") {
  elements.toast.textContent = message;
  elements.toast.dataset.kind = kind;
  elements.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 3400);
}

function showOnly(panel) {
  for (const candidate of [elements.dateGate, elements.setupPanel, elements.unlockPanel, elements.vaultPanel]) {
    candidate.hidden = candidate !== panel;
  }
}

function seoulDayKey() {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Seoul",
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const value = (type) => parts.find((part) => part.type === type)?.value || "";
  return `${value("year")}${value("month")}${value("day")}`;
}

function showVaultOrUnlock() {
  try {
    showOnly(readStoredRecord() ? elements.unlockPanel : elements.setupPanel);
  } catch (error) {
    showOnly(elements.unlockPanel);
    showToast(error.message, "error");
  }
}

function submitDailyDemoGate() {
  const day = seoulDayKey();
  if (elements.dailyDemoPassword.value.trim() !== `${day}!!`) {
    elements.dailyGateError.textContent = "코드가 맞지 않습니다. 오늘 날짜와 느낌표 두 개를 확인하세요.";
    return;
  }
  sessionStorage.setItem(DAILY_GATE_SESSION_KEY, day);
  elements.dailyDemoPassword.value = "";
  elements.dailyGateError.textContent = "";
  showVaultOrUnlock();
}

function checkDailyGateDate() {
  const acceptedDay = sessionStorage.getItem(DAILY_GATE_SESSION_KEY);
  if (acceptedDay && acceptedDay !== seoulDayKey()) {
    sessionStorage.removeItem(DAILY_GATE_SESSION_KEY);
    if (vaultKey) lockVault();
    elements.dailyDemoPassword.value = "";
    elements.dailyGateError.textContent = "";
    showOnly(elements.dateGate);
    showToast("한국 날짜가 바뀌어 화면 프롬프트가 다시 잠겼습니다.");
  }
}

function readStoredRecord() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    throw new Error("저장된 보관함을 읽을 수 없습니다. 암호화 백업이 있으면 복원해 주세요.");
  }
  validateVaultRecord(record);
  return record;
}

function validateVaultRecord(record) {
  if (
    !record ||
    record.version !== VAULT_VERSION ||
    !Number.isSafeInteger(record.iterations) ||
    record.iterations < 100_000 ||
    record.iterations > 2_000_000 ||
    typeof record.salt !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new Error("지원하지 않거나 손상된 암호화 백업 파일입니다.");
  }
  const salt = base64ToBytes(record.salt);
  const iv = base64ToBytes(record.iv);
  const ciphertext = base64ToBytes(record.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
    throw new Error("암호화 백업 파일의 형식이 올바르지 않습니다.");
  }
}

async function deriveVaultKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault() {
  if (!vaultKey || !vaultRecord) throw new Error("보관함이 잠겨 있습니다.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify({ accounts }));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, plaintext);
  vaultRecord = {
    version: VAULT_VERSION,
    iterations: vaultRecord.iterations,
    salt: vaultRecord.salt,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vaultRecord));
}

async function createVault() {
  const passphrase = elements.setupPassword.value;
  const confirmation = elements.setupPasswordConfirm.value;
  if (passphrase.length < 12) {
    showToast("보관함 암호는 12자 이상으로 설정해 주세요.", "error");
    return;
  }
  if (passphrase !== confirmation) {
    showToast("두 암호가 일치하지 않습니다.", "error");
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    vaultRecord = {
      version: VAULT_VERSION,
      iterations: PBKDF2_ITERATIONS,
      salt: bytesToBase64(salt),
      iv: "",
      ciphertext: "",
    };
    vaultKey = await deriveVaultKey(passphrase, salt, PBKDF2_ITERATIONS);
    accounts = [];
    await encryptVault();
    elements.setupPassword.value = "";
    elements.setupPasswordConfirm.value = "";
    enterVault();
  } catch (error) {
    showToast(`보관함을 만들지 못했습니다: ${error.message}`, "error");
  }
}

async function unlockVault() {
  try {
    const record = readStoredRecord();
    if (!record) throw new Error("보관함 파일을 찾을 수 없습니다.");
    const passphrase = elements.unlockPassword.value;
    const key = await deriveVaultKey(
      passphrase,
      base64ToBytes(record.salt),
      record.iterations,
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(record.iv) },
      key,
      base64ToBytes(record.ciphertext),
    );
    const decoded = JSON.parse(decoder.decode(plaintext));
    if (!decoded || !Array.isArray(decoded.accounts)) {
      throw new Error("보관함 데이터의 형식이 올바르지 않습니다.");
    }
    accounts = decoded.accounts;
    vaultKey = key;
    vaultRecord = record;
    elements.unlockPassword.value = "";
    enterVault();
  } catch {
    elements.unlockPassword.value = "";
    showToast("암호가 틀렸거나 보관함을 복호화할 수 없습니다.", "error");
  }
}

function enterVault() {
  showOnly(elements.vaultPanel);
  lastActivity = Date.now();
  renderAccounts();
  refreshCodes();
  clearInterval(refreshTimer);
  refreshTimer = setInterval(refreshCodes, 1000);
  clearInterval(autoLockTimer);
  autoLockTimer = setInterval(() => {
    if (vaultKey && Date.now() - lastActivity >= 5 * 60 * 1000) lockVault();
  }, 10_000);
}

function lockVault() {
  stopQrScanner();
  vaultKey = null;
  vaultRecord = null;
  accounts = [];
  renderGeneration += 1;
  clearInterval(refreshTimer);
  clearInterval(autoLockTimer);
  elements.accountList.replaceChildren();
  const backupExists = Boolean(localStorage.getItem(STORAGE_KEY));
  showOnly(backupExists ? elements.unlockPanel : elements.setupPanel);
  showToast("보관함을 잠갔습니다.");
}

function markActivity() {
  lastActivity = Date.now();
}

function makeAccountCard(account, code, secondsRemaining) {
  const card = document.createElement("article");
  card.className = "account-card";

  const heading = document.createElement("div");
  heading.className = "account-heading";
  const identity = document.createElement("div");
  identity.className = "account-identity";
  const issuer = document.createElement("div");
  issuer.className = "issuer";
  issuer.textContent = account.issuer || "인증 계정";
  const label = document.createElement("div");
  label.className = "account-label";
  label.textContent = account.account;
  identity.append(issuer, label);

  const removeButton = document.createElement("button");
  removeButton.className = "icon-button remove-button";
  removeButton.type = "button";
  removeButton.textContent = "삭제";
  removeButton.setAttribute("aria-label", `${account.account} 계정 삭제`);
  removeButton.addEventListener("click", () => removeAccount(account.id));
  heading.append(identity, removeButton);

  const codeRow = document.createElement("div");
  codeRow.className = "code-row";
  const codeElement = document.createElement("div");
  codeElement.className = "otp-code";
  codeElement.textContent = code || "······";
  const copyButton = document.createElement("button");
  copyButton.className = "copy-button";
  copyButton.type = "button";
  copyButton.textContent = "복사";
  copyButton.disabled = !code;
  copyButton.addEventListener("click", () => copyCode(code));
  codeRow.append(codeElement, copyButton);

  const timerRow = document.createElement("div");
  timerRow.className = "timer-row";
  const timerText = document.createElement("span");
  timerText.textContent = `${secondsRemaining ?? account.period}초 후 갱신`;
  const progress = document.createElement("div");
  progress.className = "progress-track";
  const bar = document.createElement("div");
  bar.className = "progress-bar";
  const remaining = secondsRemaining ?? account.period;
  bar.style.width = `${Math.max(0, Math.min(100, (remaining / account.period) * 100))}%`;
  if (remaining <= 5) bar.classList.add("ending");
  progress.append(bar);
  timerRow.append(timerText, progress);

  card.append(heading, codeRow, timerRow);
  return card;
}

function renderAccounts(codeMap = new Map()) {
  const sorted = [...accounts].sort((left, right) => {
    const issuerOrder = (left.issuer || "").localeCompare(right.issuer || "");
    return issuerOrder || left.account.localeCompare(right.account);
  });
  elements.accountList.replaceChildren(
    ...sorted.map((account) => {
      const result = codeMap.get(account.id);
      return makeAccountCard(account, result?.code, result?.secondsRemaining);
    }),
  );
  elements.emptyState.hidden = sorted.length > 0;
}

async function refreshCodes() {
  if (!vaultKey) return;
  const generation = ++renderGeneration;
  const current = new Map();
  try {
    for (const account of accounts) {
      const result = await generateTotp(account);
      current.set(account.id, result);
    }
    if (generation === renderGeneration) renderAccounts(current);
  } catch (error) {
    if (generation === renderGeneration) {
      showToast(`코드를 만들지 못했습니다: ${error.message}`, "error");
    }
  }
}

async function copyCode(code) {
  if (!code) return;
  try {
    await navigator.clipboard.writeText(code);
    showToast("인증 코드를 복사했습니다. 클립보드에서 사용 후 지워 주세요.");
  } catch {
    showToast("클립보드 복사에 실패했습니다. 코드를 길게 눌러 복사해 주세요.", "error");
  }
}

async function addAccountFromInputs() {
  const account = {
    id: crypto.randomUUID(),
    issuer: elements.issuer.value.trim(),
    account: elements.account.value.trim(),
    secret: elements.secret.value.replace(/[\s=-]/g, "").toUpperCase(),
    algorithm: elements.algorithm.value,
    digits: Number(elements.digits.value),
    period: Number(elements.period.value),
  };

  if (!account.account) {
    showToast("계정 이름을 입력해 주세요.", "error");
    return;
  }
  try {
    base32ToBytes(account.secret);
    if (!Number.isSafeInteger(account.period) || account.period < 1 || account.period > 86400) {
      throw new Error("갱신 주기는 1초 이상이어야 합니다.");
    }
    await generateTotp(account);
    accounts.push(account);
    await encryptVault();
    elements.addUri.value = "";
    elements.issuer.value = "";
    elements.account.value = "";
    elements.secret.value = "";
    elements.algorithm.value = "SHA1";
    elements.digits.value = "6";
    elements.period.value = "30";
    stopQrScanner();
    elements.addDialog.close();
    renderAccounts();
    await refreshCodes();
    showToast("계정을 이 브라우저의 암호화 보관함에 저장했습니다.");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function removeAccount(id) {
  const account = accounts.find((candidate) => candidate.id === id);
  if (!account || !confirm(`${account.issuer ? `${account.issuer} · ` : ""}${account.account} 계정을 삭제할까요?`)) {
    return;
  }
  accounts = accounts.filter((candidate) => candidate.id !== id);
  try {
    await encryptVault();
    renderAccounts();
    await refreshCodes();
    showToast("계정을 삭제했습니다.");
  } catch (error) {
    showToast(`저장하지 못했습니다: ${error.message}`, "error");
  }
}

function fillFormFromUri() {
  try {
    const parsed = parseOtpAuthUri(elements.addUri.value);
    elements.issuer.value = parsed.issuer;
    elements.account.value = parsed.account;
    elements.secret.value = parsed.secret;
    elements.algorithm.value = parsed.algorithm;
    elements.digits.value = String(parsed.digits);
    elements.period.value = String(parsed.period);
    showToast("설정 URI를 읽었습니다. 계정 정보를 확인한 뒤 추가하세요.");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function stopQrScanner() {
  clearInterval(qrTimer);
  qrTimer = null;
  qrStream?.getTracks().forEach((track) => track.stop());
  qrStream = null;
  elements.video.srcObject = null;
  elements.scannerPanel.hidden = true;
  qrBusy = false;
}

async function startQrScanner() {
  if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
    showToast("카메라 스캔에는 HTTPS와 카메라 권한이 필요합니다. otpauth URI를 붙여 넣어도 됩니다.", "error");
    return;
  }
  if (!("BarcodeDetector" in window)) {
    showToast("이 브라우저는 내장 QR 스캔을 지원하지 않습니다. otpauth URI를 붙여 넣어 주세요.", "error");
    return;
  }

  try {
    const formats = await BarcodeDetector.getSupportedFormats();
    if (!formats.includes("qr_code")) {
      showToast("이 브라우저에서는 QR 스캔을 사용할 수 없습니다. otpauth URI를 붙여 넣어 주세요.", "error");
      return;
    }
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    qrStream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" } },
    });
    elements.video.srcObject = qrStream;
    elements.scannerPanel.hidden = false;
    await elements.video.play();

    qrTimer = setInterval(async () => {
      if (qrBusy || !elements.video.videoWidth) return;
      qrBusy = true;
      try {
        const results = await detector.detect(elements.video);
        const uri = results.find((result) => result.rawValue?.startsWith("otpauth://totp/"))?.rawValue;
        if (uri) {
          elements.addUri.value = uri;
          fillFormFromUri();
          stopQrScanner();
        }
      } catch {
        // Continue scanning; startup and permission errors are shown to the user.
      } finally {
        qrBusy = false;
      }
    }, 350);
  } catch (error) {
    stopQrScanner();
    showToast(`카메라를 열지 못했습니다: ${error.message}`, "error");
  }
}

function exportEncryptedBackup() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    showToast("내보낼 암호화 보관함이 없습니다.", "error");
    return;
  }
  const blob = new Blob([raw], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "authenticator-encrypted-backup.json";
  link.click();
  URL.revokeObjectURL(url);
  showToast("암호화 백업을 저장했습니다. 복원에는 보관함 암호가 필요합니다.");
}

async function importEncryptedBackup(file) {
  if (!file) return;
  try {
    const record = JSON.parse(await file.text());
    validateVaultRecord(record);
    if (localStorage.getItem(STORAGE_KEY) && !confirm("현재 브라우저의 보관함을 이 백업으로 바꿀까요?")) {
      elements.backupImport.value = "";
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    lockVault();
    showOnly(elements.unlockPanel);
    showToast("백업을 가져왔습니다. 백업을 만들 때 사용한 암호로 잠금을 해제하세요.");
  } catch (error) {
    showToast(`백업을 가져오지 못했습니다: ${error.message}`, "error");
  } finally {
    elements.backupImport.value = "";
  }
}

function initialize() {
  if (!globalThis.crypto?.subtle || !window.isSecureContext) {
    showOnly(elements.setupPanel);
    elements.setupPanel.replaceChildren();
    const heading = document.createElement("h1");
    heading.textContent = "보안 연결이 필요합니다";
    const message = document.createElement("p");
    message.textContent = "이 앱은 HTTPS와 브라우저 Web Crypto가 필요합니다.";
    elements.setupPanel.append(heading, message);
    return;
  }

  if (sessionStorage.getItem(DAILY_GATE_SESSION_KEY) === seoulDayKey()) {
    showVaultOrUnlock();
  } else {
    showOnly(elements.dateGate);
  }

  $("#daily-gate-submit").addEventListener("click", submitDailyDemoGate);
  elements.dailyDemoPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitDailyDemoGate();
  });
  dailyGateTimer = setInterval(checkDailyGateDate, 30_000);
  $("#create-vault-button").addEventListener("click", createVault);
  $("#unlock-submit-button").addEventListener("click", unlockVault);
  $("#save-account-button").addEventListener("click", addAccountFromInputs);
  $("#add-account-button").addEventListener("click", () => elements.addDialog.showModal());
  $("#cancel-add").addEventListener("click", () => {
    stopQrScanner();
    elements.addDialog.close();
  });
  $("#parse-uri-button").addEventListener("click", fillFormFromUri);
  $("#scan-qr-button").addEventListener("click", startQrScanner);
  $("#stop-qr-button").addEventListener("click", stopQrScanner);
  $("#lock-button").addEventListener("click", lockVault);
  $("#backup-button").addEventListener("click", exportEncryptedBackup);
  elements.backupImport.addEventListener("change", (event) => importEncryptedBackup(event.target.files[0]));
  elements.addDialog.addEventListener("close", stopQrScanner);
  for (const eventName of ["pointerdown", "keydown", "touchstart"]) {
    document.addEventListener(eventName, markActivity, { passive: true });
  }
  for (const input of [elements.setupPassword, elements.setupPasswordConfirm]) {
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") createVault();
    });
  }
  elements.unlockPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") unlockVault();
  });
}

initialize();
