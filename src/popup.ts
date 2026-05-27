interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: string; // enabled symbol chars, empty = none
}

const CHARSETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
} as const;

const ALL_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

// Maps printable ASCII (0x21–0x7E) to their full-width Unicode equivalents.
function toFullWidth(str: string): string {
  return Array.from(str).map(ch => {
    const code = ch.charCodeAt(0);
    return code >= 0x21 && code <= 0x7E ? String.fromCharCode(code + 0xFEE0) : ch;
  }).join("");
}

// Batches crypto.getRandomValues calls; rejection-samples to avoid modulo bias.
function makeRng(): (max: number) => number {
  const buf = new Uint8Array(128);
  let pos = buf.length;
  return function (max: number): number {
    const limit = 256 - (256 % max);
    for (;;) {
      if (pos >= buf.length) {
        crypto.getRandomValues(buf);
        pos = 0;
      }
      const v = buf[pos++];
      if (v < limit) return v % max;
    }
  };
}

function shuffled(chars: string[], rng: (max: number) => number): string[] {
  const arr = [...chars];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = rng(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function generatePassword(opts: PasswordOptions): string {
  const charsets: string[] = (Object.keys(CHARSETS) as Array<keyof typeof CHARSETS>)
    .filter((k) => opts[k])
    .map((k) => CHARSETS[k]);
  if (opts.symbols) charsets.push(opts.symbols);

  if (charsets.length === 0) return "";

  const rng = makeRng();
  const fullCharset = charsets.join("");
  const chars: string[] = [];

  // Guarantee at least one character from each enabled charset.
  for (const cs of charsets) {
    chars.push(cs[rng(cs.length)]);
  }

  // Fill remaining positions from the combined charset.
  while (chars.length < opts.length) {
    chars.push(fullCharset[rng(fullCharset.length)]);
  }

  return shuffled(chars, rng).join("");
}

// Entropy-based strength: bits = log2(charsetSize^length)
function calcStrength(opts: PasswordOptions): { bits: number; label: string; color: string } {
  const poolSize =
    (Object.keys(CHARSETS) as Array<keyof typeof CHARSETS>)
      .filter((k) => opts[k])
      .reduce((sum, k) => sum + CHARSETS[k].length, 0) + opts.symbols.length;
  if (poolSize === 0) return { bits: 0, label: "", color: "#3e3e54" };

  const bits = Math.log2(poolSize) * opts.length;

  if (bits < 40) return { bits, label: "Very Weak", color: "#ef4444" };
  if (bits < 60) return { bits, label: "Weak", color: "#f97316" };
  if (bits < 80) return { bits, label: "Fair", color: "#eab308" };
  if (bits < 100) return { bits, label: "Strong", color: "#22c55e" };
  return { bits, label: "Very Strong", color: "#34d399" };
}

// ── DOM references ──────────────────────────────────────────────────────────

const passwordOutput = document.getElementById("password-output") as HTMLSpanElement;
const copyBtn = document.getElementById("copy-btn") as HTMLButtonElement;
const copyFeedback = document.getElementById("copy-feedback") as HTMLDivElement;
const generateBtn = document.getElementById("generate-btn") as HTMLButtonElement;
const lengthSlider = document.getElementById("length-slider") as HTMLInputElement;
const lengthNumber = document.getElementById("length-number") as HTMLInputElement;
const cbUppercase = document.getElementById("cb-uppercase") as HTMLInputElement;
const cbLowercase = document.getElementById("cb-lowercase") as HTMLInputElement;
const cbNumbers = document.getElementById("cb-numbers") as HTMLInputElement;
const symbolCheckboxes = Array.from(document.querySelectorAll<HTMLInputElement>("[data-symbol]"));
const cbFullWidth = document.getElementById("cb-fullwidth") as HTMLInputElement;
const strengthBar = document.getElementById("strength-bar") as HTMLDivElement;
const strengthLabel = document.getElementById("strength-label") as HTMLDivElement;
const optionsSection = document.querySelector(".options") as HTMLDivElement;
const optionsHeader = document.querySelector(".options-header") as HTMLDivElement;

// ── State ───────────────────────────────────────────────────────────────────

let rawPassword = "";
let currentPassword = "";
let copyFeedbackTimer: ReturnType<typeof setTimeout> | null = null;

// ── Helpers ─────────────────────────────────────────────────────────────────

function getOptions(): PasswordOptions {
  return {
    length: clampLength(parseInt(lengthSlider.value, 10)),
    uppercase: cbUppercase.checked,
    lowercase: cbLowercase.checked,
    numbers: cbNumbers.checked,
    symbols: symbolCheckboxes.filter((cb) => cb.checked).map((cb) => cb.dataset.symbol!).join(""),
  };
}

function clampLength(n: number): number {
  return Math.max(8, Math.min(64, isNaN(n) ? 16 : n));
}

function updateStrengthUI(opts: PasswordOptions): void {
  const { bits, label, color } = calcStrength(opts);
  const pct = Math.min(100, (bits / 120) * 100);
  strengthBar.style.width = `${pct}%`;
  strengthBar.style.backgroundColor = color;
  strengthLabel.textContent = label ? `${label} (~${Math.round(bits)} bits of entropy)` : "";
  strengthLabel.style.color = color;
}

function generate(): void {
  const opts = getOptions();
  rawPassword = generatePassword(opts);
  currentPassword = cbFullWidth.checked ? toFullWidth(rawPassword) : rawPassword;
  passwordOutput.textContent = currentPassword || "—";
  copyBtn.disabled = currentPassword.length === 0;
  updateStrengthUI(opts);
  clearCopyFeedback();
}

function clearCopyFeedback(): void {
  if (copyFeedbackTimer !== null) clearTimeout(copyFeedbackTimer);
  copyFeedback.textContent = "";
  copyFeedback.style.color = "";
}

// ── Event listeners ──────────────────────────────────────────────────────────

generateBtn.addEventListener("click", generate);

optionsHeader.addEventListener("click", () => {
  optionsSection.classList.toggle("expanded");
});

lengthSlider.addEventListener("input", () => {
  lengthNumber.value = lengthSlider.value;
  updateStrengthUI(getOptions());
});

lengthNumber.addEventListener("change", () => {
  const clamped = clampLength(parseInt(lengthNumber.value, 10));
  lengthNumber.value = String(clamped);
  lengthSlider.value = String(clamped);
  updateStrengthUI(getOptions());
});

[cbUppercase, cbLowercase, cbNumbers].forEach((cb) => {
  cb.addEventListener("change", () => updateStrengthUI(getOptions()));
});

symbolCheckboxes.forEach((cb) => {
  cb.addEventListener("change", () => updateStrengthUI(getOptions()));
});

cbFullWidth.addEventListener("change", () => {
  currentPassword = cbFullWidth.checked ? toFullWidth(rawPassword) : rawPassword;
  passwordOutput.textContent = currentPassword || "—";
  copyBtn.disabled = currentPassword.length === 0;
  clearCopyFeedback();
});

copyBtn.addEventListener("click", async () => {
  if (!currentPassword) return;
  try {
    await navigator.clipboard.writeText(currentPassword);
    clearCopyFeedback();
    copyFeedback.textContent = "Copied!";
    copyFeedbackTimer = setTimeout(() => {
      copyFeedback.textContent = "";
    }, 2000);
  } catch {
    copyFeedback.textContent = "Copy failed — select manually";
    copyFeedback.style.color = "#f87171";
  }
});

// ── Init ─────────────────────────────────────────────────────────────────────

generate();
