import { generateTotp } from "./totp.js";

const SEEDS_URL = "./seeds.enc.json";
const LEGACY_STORAGE_KEY = "webtronics-extra-accounts-v1";
const decoder = new TextDecoder();
const encoder = new TextEncoder();

// Accounts exist only as AES-GCM ciphertext; they are filled in after unlock.
// Adding accounts from the page is intentionally not supported.
let accounts = [];
let unlocked = false;

const $ = (selector) => document.querySelector(selector);
const list = $("#account-list");
const toast = $("#toast");

// Remove accounts that an earlier version may have stored in this browser.
try {
  localStorage.removeItem(LEGACY_STORAGE_KEY);
} catch {
  // Storage may be unavailable; nothing to clean up then.
}

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

  const timer = document.createElement("div");
  timer.className = "timer";
  timer.setAttribute("aria-label", "새 코드까지 남은 시간");

  const seconds = document.createElement("span");
  seconds.className = "timer-seconds";
  seconds.textContent = "--초";

  const pie = document.createElement("div");
  pie.className = "timer-pie";
  pie.setAttribute("aria-hidden", "true");
  timer.append(seconds, pie);
  codeRow.append(code, timer);
  row.append(name, codeRow);

  const state = { code: "", codeEl: code, pieEl: pie, secondsEl: seconds };
  const copy = () => state.code && copyCode(state.code);
  row.addEventListener("click", copy);
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      copy();
    }
  });

  rows.set(account.id, state);
  return row;
}

function render() {
  rows.clear();
  list.replaceChildren(...accounts.map(buildRow));
  refresh();
}

async function refresh() {
  for (const account of accounts) {
    const state = rows.get(account.id);
    if (!state) continue;
    try {
      const { code, secondsRemaining } = await generateTotp(account);
      state.code = code;
      state.codeEl.textContent = groupDigits(code);
      const ending = secondsRemaining <= 5;
      state.codeEl.classList.toggle("ending", ending);
      state.secondsEl.textContent = `${secondsRemaining}초`;
      state.secondsEl.classList.toggle("ending", ending);
      state.pieEl.classList.toggle("ending", ending);
      const percent = Math.max(0, Math.min(100, (secondsRemaining / account.period) * 100));
      state.pieEl.style.background = `conic-gradient(${ending ? "#f48771" : "#569cd6"} 0 ${percent}%, #3c3c3c 0)`;
      state.secondsEl.setAttribute("aria-label", `새 코드까지 ${secondsRemaining}초`);
    } catch {
      state.codeEl.textContent = "오류";
      state.secondsEl.textContent = "--초";
    }
  }
}

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
    accounts = await decryptSeeds(input.value);
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
  accounts = [];
  rows.clear();
  list.replaceChildren();
  showApp(false);
  $("#gate-password").focus();
}

$("#gate-form").addEventListener("submit", unlock);
$("#lock-button").addEventListener("click", lock);
setInterval(() => { if (unlocked) refresh(); }, 1000);
showApp(false);
