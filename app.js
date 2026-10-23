import { generateTotp, parseOtpAuthUri } from "./totp.js";

const STORAGE_KEY = "webtronics-extra-accounts-v1";

const SEEDS_URL = "./seeds.enc.json";
const decoder = new TextDecoder();
const encoder = new TextEncoder();

// Shared accounts exist only as AES-GCM ciphertext; they are filled in after unlock.
let builtIn = [];
let unlocked = false;

const $ = (selector) => document.querySelector(selector);
const list = $("#account-list");
const dialog = $("#add-dialog");
const toast = $("#toast");

function loadExtra() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveExtra(accounts) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
  } catch {
    showToast("이 브라우저에는 저장할 수 없습니다.");
  }
}

let extra = loadExtra();
const allAccounts = () => [...builtIn, ...extra];

let toastTimer;
function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

function groupDigits(code) {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

async function copyCode(code) {
  try {
    await navigator.clipboard.writeText(code);
    showToast("코드를 복사했습니다");
  } catch {
    showToast("복사하지 못했습니다. 코드를 직접 선택해 주세요.");
  }
}

const rows = new Map();

function buildRow(account) {
  const row = document.createElement("article");
  row.className = "account-card";
  row.tabIndex = 0;
  row.setAttribute("role", "button");

  const name = document.createElement("div");
  name.className = "issuer";
  name.textContent = account.issuer ? `${account.issuer} (${account.account})` : account.account;

  const codeRow = document.createElement("div");
  codeRow.className = "code-row";
  const code = document.createElement("div");
  code.className = "otp-code";
  code.textContent = "······";
  const pie = document.createElement("div");
  pie.className = "timer-pie";
  codeRow.append(code, pie);

  row.append(name, codeRow);

  const state = { code: "", codeEl: code, pieEl: pie };
  const copy = () => state.code && copyCode(state.code);
  row.addEventListener("click", copy);
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      copy();
    }
  });

  if (extra.some((item) => item.id === account.id)) {
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-button";
    remove.textContent = "삭제";
    remove.setAttribute("aria-label", `${account.account} 삭제`);
    remove.addEventListener("click", (event) => {
      event.stopPropagation();
      if (!confirm(`"${account.account}"을(를) 삭제할까요?`)) return;
      extra = extra.filter((item) => item.id !== account.id);
      saveExtra(extra);
      render();
    });
    row.append(remove);
  }

  rows.set(account.id, state);
  return row;
}

function render() {
  rows.clear();
  list.replaceChildren(...allAccounts().map(buildRow));
  refresh();
}

async function refresh() {
  for (const account of allAccounts()) {
    const state = rows.get(account.id);
    if (!state) continue;
    try {
      const { code, secondsRemaining } = await generateTotp(account);
      state.code = code;
      state.codeEl.textContent = groupDigits(code);
      const ending = secondsRemaining <= 5;
      state.codeEl.classList.toggle("ending", ending);
      const percent = Math.max(0, Math.min(100, (secondsRemaining / account.period) * 100));
      state.pieEl.style.background = `conic-gradient(${ending ? "#d93025" : "#1a73e8"} 0 ${percent}%, #e8eaed 0)`;
    } catch {
      state.codeEl.textContent = "오류";
    }
  }
}

function openDialog() {
  $("#add-uri").value = "";
  $("#add-name").value = "";
  $("#add-error").textContent = "";
  dialog.showModal();
}

function addFromInput() {
  const raw = $("#add-uri").value.trim();
  const name = $("#add-name").value.trim();
  let parsed;
  try {
    if (/^otpauth:\/\//i.test(raw)) {
      parsed = parseOtpAuthUri(raw);
    } else {
      parsed = {
        issuer: "",
        account: name || "새 계정",
        secret: raw.replace(/[\s=-]/g, "").toUpperCase(),
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      };
    }
    // Throws if the secret is not valid Base32.
    return generateTotp(parsed).then(() => {
      if (name) parsed.account = name;
      extra = [...extra, { id: crypto.randomUUID(), ...parsed }];
      saveExtra(extra);
      return true;
    });
  } catch (error) {
    return Promise.reject(error);
  }
}

$("#add-button").addEventListener("click", openDialog);
$("#add-cancel").addEventListener("click", () => dialog.close());
$("#add-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await addFromInput();
    dialog.close();
    render();
  } catch (error) {
    $("#add-error").textContent = `추가하지 못했습니다: ${error.message}`;
  }
});

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function decryptSeeds(password) {
  const response = await fetch(SEEDS_URL, { cache: "no-store" });
  if (!response.ok) throw new Error("seed file");
  const record = await response.json();
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: base64ToBytes(record.salt), iterations: record.iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(record.iv) }, key, base64ToBytes(record.ciphertext));
  const decoded = JSON.parse(decoder.decode(plain));
  if (!Array.isArray(decoded.accounts)) throw new Error("format");
  return decoded.accounts;
}

function showApp(show) {
  $("#gate").hidden = show;
  $("#app").hidden = !show;
}

async function unlock(event) {
  event.preventDefault();
  const input = $("#gate-password");
  const error = $("#gate-error");
  error.textContent = "";
  $("#gate-submit").disabled = true;
  try {
    builtIn = await decryptSeeds(input.value);
    unlocked = true;
    input.value = "";
    showApp(true);
    render();
  } catch {
    error.textContent = "비밀번호가 맞지 않습니다.";
    input.select();
  } finally {
    $("#gate-submit").disabled = false;
  }
}

function lock() {
  unlocked = false;
  builtIn = [];
  rows.clear();
  list.replaceChildren();
  showApp(false);
  $("#gate-password").focus();
}

$("#gate-form").addEventListener("submit", unlock);
$("#lock-button").addEventListener("click", lock);
setInterval(() => { if (unlocked) refresh(); }, 1000);
showApp(false);
