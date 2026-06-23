import init, {
  BeeConnect,
  ensure_mining_keys_propagated,
  gen_mining_keys,
  get_miner_address_by_wallet_name,
  type InitOutput,
  Miner,
  Wallet,
} from "@teamgosh/bee-sdk";

import { QRCodeSVG } from "qrcode.react";
import Logo from "/nackl.svg";
import "./App.css";

import { useEffect, useRef, useState } from "react";

const APP_ID = "0x0000000000000000000000000000000000000000000000000000000000000000";
const ENDPOINTS = ["https://mainnet.ackinacki.org"];
const API_URL = "https://app-backend-dev.ackinacki.org/api";
const ACTIVE_SESSION_STORAGE_KEY = "bee_connect_demo_active_session_v1";
const MINING_KEYS_STORAGE_PREFIX = "bee_connect_demo_mining_keys_v1";
const SESSION_POLL_INTERVAL_MS = 10000;
const BALANCE_POLL_INTERVAL_MS = 10000;
const MINER_DATA_POLL_INTERVAL_MS = 5000;
const BEE_SDK_WASM_URL = new URL("../../../../bee_sdk/pkg/bee_sdk_bg.wasm", import.meta.url);
let beeSdkInitPromise: Promise<InitOutput> | null = null;

async function initBeeSdk() {
  if (!beeSdkInitPromise) {
    beeSdkInitPromise = init({
      module_or_path: BEE_SDK_WASM_URL,
    });
  }
  await beeSdkInitPromise;
}

async function getMinerAddress(walletName: string) {
  await initBeeSdk();
  return await get_miner_address_by_wallet_name({
    client_config: {
      network: {
        endpoints: ENDPOINTS,
      },
    },
    wallet_name: walletName,
  });
}

async function waitForMiningKeysPropagation(walletName: string, ownerPublic: string) {
  const minerAddress = await getMinerAddress(walletName);

  await ensure_mining_keys_propagated({
    client_config: {
      network: {
        endpoints: ENDPOINTS,
      },
    },
    miner_address: minerAddress,
    app_id: APP_ID,
    expected_owner_public: ownerPublic,
    max_attempts: 120,
    interval_ms: 2000,
  });

  return minerAddress;
}

async function initMiner(minerAddress: string, ownerPublic: string, ownerSecret: string) {
  await initBeeSdk();
  return await Miner.new(ENDPOINTS, APP_ID, minerAddress, ownerPublic, ownerSecret);
}

function minerCallback(message: string) {
  console.log(`[MINER_CALLBACK]: ${message}`);
}

type WalletConnection = {
  walletName: string;
  walletAddress: string;
  profileAddress: string;
  sessionId: string;
  description: string;
  sessionStateJson: string;
  /** Inline challenge: present when connected with nonce verification. */
  inlineChallenge?: {
    nonce: string;
    signature: string;
    epkPublic: string;
  };
};

type StoredMiningKeys = {
  ownerPublic: string;
  ownerSecret: string;
  minerAddress: string | null;
  areKeysPropagated: boolean;
};

type MinerCallbackPayload = {
  action?: string;
  data?: {
    status?: string;
    [key: string]: unknown;
  } | null;
  error?: string | null;
};

type MinerDebugInfo = {
  tapSum: string;
  tapSum5m: string;
  epochStart: string;
  epoch5mStart: string;
  updatedAt: string;
};

function readStoredWalletConnection(): WalletConnection | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = window.localStorage.getItem(ACTIVE_SESSION_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<WalletConnection>;
    if (
      typeof parsed.walletName !== "string" ||
      typeof parsed.walletAddress !== "string" ||
      typeof parsed.profileAddress !== "string" ||
      typeof parsed.sessionId !== "string" ||
      typeof parsed.description !== "string" ||
      typeof parsed.sessionStateJson !== "string"
    ) {
      return null;
    }

    return {
      walletName: parsed.walletName,
      walletAddress: parsed.walletAddress,
      profileAddress: parsed.profileAddress,
      sessionId: parsed.sessionId,
      description: parsed.description,
      sessionStateJson: parsed.sessionStateJson,
    };
  } catch {
    return null;
  }
}

function writeStoredWalletConnection(connection: WalletConnection | null) {
  if (typeof window === "undefined") {
    return;
  }

  if (!connection) {
    window.localStorage.removeItem(ACTIVE_SESSION_STORAGE_KEY);
    return;
  }

  window.localStorage.setItem(ACTIVE_SESSION_STORAGE_KEY, JSON.stringify(connection));
}

function miningKeysStorageKey(connection: WalletConnection): string {
  return `${MINING_KEYS_STORAGE_PREFIX}:${connection.profileAddress}:${APP_ID}`;
}

function readStoredMiningKeys(connection: WalletConnection): StoredMiningKeys | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = window.localStorage.getItem(miningKeysStorageKey(connection));
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<StoredMiningKeys>;
    if (
      typeof parsed.ownerPublic !== "string" ||
      typeof parsed.ownerSecret !== "string" ||
      typeof parsed.areKeysPropagated !== "boolean" ||
      (parsed.minerAddress !== null && typeof parsed.minerAddress !== "string")
    ) {
      return null;
    }

    return {
      ownerPublic: parsed.ownerPublic,
      ownerSecret: parsed.ownerSecret,
      minerAddress: parsed.minerAddress ?? null,
      areKeysPropagated: parsed.areKeysPropagated,
    };
  } catch {
    return null;
  }
}

function writeStoredMiningKeys(connection: WalletConnection, value: StoredMiningKeys | null) {
  if (typeof window === "undefined") {
    return;
  }

  const key = miningKeysStorageKey(connection);
  if (!value) {
    window.localStorage.removeItem(key);
    return;
  }

  window.localStorage.setItem(key, JSON.stringify(value));
}

function clearStoredMiningKeys(connection: WalletConnection) {
  writeStoredMiningKeys(connection, null);
}

function formatNanoToDisplay(value: string, decimals = 9, fractionDigits = 4): string {
  let amount = 0n;
  try {
    amount = BigInt(value);
  } catch {
    return "0.0000";
  }

  const base = 10n ** BigInt(decimals);
  const whole = amount / base;
  const frac = amount % base;
  const fracScaled = (frac * 10n ** BigInt(fractionDigits)) / base;

  return `${whole.toString()}.${fracScaled.toString().padStart(fractionDigits, "0")}`;
}

async function isSessionStillActive(connection: WalletConnection): Promise<boolean> {
  await initBeeSdk();
  const beeConnect = new BeeConnect();
  const resolvedProfileAddress = await beeConnect.resolve_profile_address(
    ENDPOINTS,
    connection.description,
  );
  if (
    resolvedProfileAddress.trim().toLowerCase() !== connection.profileAddress.trim().toLowerCase()
  ) {
    console.warn(
      "[SESSION_MONITOR] profile address mismatch — resolved:",
      resolvedProfileAddress,
      "stored:",
      connection.profileAddress,
    );
    return false;
  }

  const deployed = await beeConnect.is_session_profile_deployed(ENDPOINTS, connection.description);
  if (!deployed) {
    console.warn(
      "[SESSION_MONITOR] session profile NOT deployed for description:",
      connection.description,
    );
  }
  return deployed;
}

type WalletConnectProps = {
  onConnected: (connection: WalletConnection) => void;
};

function WalletConnect({ onConnected }: WalletConnectProps) {
  const [isCreatingSession, setIsCreatingSession] = useState(false);
  const [isWaitingWallet, setIsWaitingWallet] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deepLink, setDeepLink] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [connectMode, setConnectMode] = useState<"simple" | "verified" | null>(null);
  const waitTokenRef = useRef(0);

  const cancelWaiting = () => {
    waitTokenRef.current += 1;
    setIsWaitingWallet(false);
    setDeepLink(null);
    setSessionId(null);
    setConnectMode(null);
  };

  const handleConnect = async (withChallenge: boolean) => {
    try {
      setIsCreatingSession(true);
      setError(null);
      setDeepLink(null);
      setSessionId(null);
      setIsWaitingWallet(false);
      setConnectMode(withChallenge ? "verified" : "simple");

      const beeConnect = new BeeConnect();
      const nonce = withChallenge ? generateNonce() : undefined;

      console.log("[CONNECT] creating session", { withChallenge, nonce });
      const session = beeConnect.create_shared_key_session(APP_ID, 300, nonce ?? null);
      setDeepLink(session.deep_link);
      setSessionId(session.session_id);

      const waitToken = waitTokenRef.current + 1;
      waitTokenRef.current = waitToken;
      setIsWaitingWallet(true);

      void (async () => {
        try {
          console.log("[CONNECT] calling wait_wallet_hello...", {
            session_id: session.session_id,
            withChallenge,
          });
          const hello = await beeConnect.wait_wallet_hello(
            ENDPOINTS,
            session.session_id,
            session.description,
            session.client_dh_secret,
            session.created_at,
            120,
            1000,
          );

          console.log("[CONNECT] wait_wallet_hello succeeded:", {
            wallet_name: hello.wallet_name,
            wallet_address: hello.wallet_address,
            profile_address: hello.profile_address,
            has_signature: !!hello.signature,
          });

          if (waitToken !== waitTokenRef.current) {
            return;
          }

          const connection: WalletConnection = {
            walletName: hello.wallet_name,
            walletAddress: hello.wallet_address,
            profileAddress: hello.profile_address,
            sessionId: session.session_id,
            description: session.description,
            sessionStateJson: hello.session_state_json,
          };

          if (withChallenge && nonce && hello.signature) {
            const nonceMatch = hello.nonce === nonce;
            console.log("[CONNECT] inline challenge result:", {
              nonceMatch,
              nonce: hello.nonce,
              signature: hello.signature,
              epk_public: hello.epk_public,
            });
            connection.inlineChallenge = {
              nonce: hello.nonce!,
              signature: hello.signature!,
              epkPublic: hello.epk_public ?? "",
            };
          } else if (withChallenge) {
            console.warn("[CONNECT] requested challenge but wallet did not sign — old wallet?");
          }

          onConnected(connection);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          console.error("[CONNECT] wait_wallet_hello failed:", msg);
          if (waitToken !== waitTokenRef.current) {
            return;
          }
          setError(msg);
        } finally {
          if (waitToken === waitTokenRef.current) {
            setIsWaitingWallet(false);
          }
        }
      })();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsCreatingSession(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", alignItems: "center" }}>
      {!deepLink && (
        <div style={{ display: "flex", gap: "10px" }}>
          <button type="button" onClick={() => handleConnect(false)} disabled={isCreatingSession}>
            {isCreatingSession && connectMode === "simple" ? "Creating..." : "Connect"}
          </button>
          <button type="button" onClick={() => handleConnect(true)} disabled={isCreatingSession}>
            {isCreatingSession && connectMode === "verified" ? "Creating..." : "Connect + Verify"}
          </button>
        </div>
      )}

      {deepLink && (
        <div className="connect-card">
          <button
            type="button"
            className="connect-close"
            onClick={cancelWaiting}
            aria-label="Close connect card"
            title="Close"
          >
            ×
          </button>
          <div className="connect-card-title">
            {connectMode === "verified"
              ? "Scan QR — connect with ownership verification"
              : "Scan QR in wallet app"}
          </div>
          <div className="connect-qr-wrap">
            <QRCodeSVG className="connect-qr" value={deepLink} size={280} />
          </div>
          <div className="connect-actions">
            <a href={deepLink} target="_blank" rel="noreferrer" className="connect-open">
              Open wallet
            </a>
          </div>
          <div className="connect-status">
            {isWaitingWallet
              ? `Waiting for wallet confirmation...${sessionId ? ` (${sessionId})` : ""}`
              : "Session created. Open wallet and confirm connection."}
          </div>
        </div>
      )}

      {error && <div style={{ color: "#e74c3c" }}>{error}</div>}
    </div>
  );
}

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function VerifyWalletPanel({
  connection,
  onSessionDesync,
}: {
  connection: WalletConnection;
  onSessionDesync: () => void;
}) {
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyStatus, setVerifyStatus] = useState<string | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{
    nonce: string;
    signature: string;
    walletAddress: string;
  } | null>(null);

  const handleVerify = async () => {
    try {
      setIsVerifying(true);
      setVerifyError(null);
      setVerifyStatus(null);
      setVerifyResult(null);

      const nonce = generateNonce();
      console.log("[VERIFY] starting. nonce:", nonce, "sessionId:", connection.sessionId);
      setVerifyStatus(`Backend generated nonce: ${nonce}. Sending sign_challenge...`);

      const beeConnect = new BeeConnect();

      // 1. Send sign_challenge (c→w)
      console.log("[VERIFY] sending request_sign_challenge...");
      const challengeResult = await beeConnect.request_sign_challenge(
        ENDPOINTS,
        connection.sessionId,
        connection.description,
        connection.sessionStateJson,
        nonce,
        30,
        1000,
      );
      console.log(
        "[VERIFY] sign_challenge sent. sent_at:",
        challengeResult.sent_at,
        "message_id:",
        challengeResult.message_id,
      );

      // Do NOT persist session state yet — if wait_challenge_response times out,
      // the DH chain stays at the pre-challenge position so retry is possible.
      setVerifyStatus(`sign_challenge sent. Waiting for wallet to sign (nonce: ${nonce})...`);

      // 2. Wait for challenge_response (w→c)
      console.log("[VERIFY] calling wait_challenge_response...");
      const response = await beeConnect.wait_challenge_response(
        ENDPOINTS,
        connection.sessionId,
        connection.description,
        challengeResult.updated_session_state_json,
        challengeResult.sent_at,
        120,
        2000,
      );
      console.log(
        "[VERIFY] challenge_response received. nonce match:",
        response.nonce === nonce,
        "wallet:",
        response.wallet_address,
      );

      // Persist session state only after successful response —
      // both sign_challenge outbound rekey and challenge_response inbound rekey.
      const finalState =
        response.updated_session_state_json ?? challengeResult.updated_session_state_json;
      if (finalState) {
        connection.sessionStateJson = finalState;
        writeStoredWalletConnection(connection);
      }

      setVerifyResult({
        nonce: response.nonce,
        signature: response.signature,
        walletAddress: response.wallet_address,
      });
      setVerifyStatus(
        response.nonce === nonce
          ? "Wallet ownership verified! Nonce matches."
          : `WARNING: nonce mismatch! Expected ${nonce}, got ${response.nonce}`,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[VERIFY] error:", msg);
      if (msg.includes("session_desync")) {
        console.error("[VERIFY] session_desync detected — will drop connection");
        setVerifyError("Session out of sync. Please reconnect your wallet.");
        onSessionDesync();
      } else {
        setVerifyError(msg);
      }
      setVerifyStatus(null);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div
      style={{
        border: "1px solid rgba(255, 255, 255, 0.15)",
        borderRadius: "10px",
        padding: "14px 16px",
        background: "rgba(255, 255, 255, 0.03)",
        display: "flex",
        flexDirection: "column",
        gap: "10px",
        width: "min(720px, 92vw)",
      }}
    >
      <div style={{ fontWeight: 600 }}>Backend Auth (sign_challenge)</div>
      <button type="button" onClick={handleVerify} disabled={isVerifying}>
        {isVerifying ? "Verifying wallet ownership..." : "Verify wallet ownership"}
      </button>
      {verifyStatus && (
        <div style={{ color: "rgba(255, 255, 255, 0.72)", fontSize: "0.85rem" }}>
          {verifyStatus}
        </div>
      )}
      {verifyResult && (
        <div
          style={{
            fontSize: "0.8rem",
            fontFamily: "monospace",
            color: "rgba(255, 255, 255, 0.65)",
            wordBreak: "break-all",
          }}
        >
          <div>nonce: {verifyResult.nonce}</div>
          <div>signature: {verifyResult.signature}</div>
          <div>wallet: {verifyResult.walletAddress}</div>
        </div>
      )}
      {verifyError && <div style={{ color: "#e74c3c", fontSize: "0.85rem" }}>{verifyError}</div>}
    </div>
  );
}

function MinerPanel({ connection }: { connection: WalletConnection }) {
  const [miner, setMiner] = useState<Miner>();
  const minerRef = useRef<Miner | undefined>(undefined);
  const storedKeys = readStoredMiningKeys(connection);
  const [minerAddress, setMinerAddress] = useState<string | null>(storedKeys?.minerAddress ?? null);
  const [ownerPublic, setOwnerPublic] = useState<string | null>(storedKeys?.ownerPublic ?? null);
  const [ownerSecret, setOwnerSecret] = useState<string | null>(storedKeys?.ownerSecret ?? null);
  const [areKeysPropagated, setAreKeysPropagated] = useState(
    storedKeys?.areKeysPropagated ?? false,
  );
  const [isWaitingKeysPropagation, setIsWaitingKeysPropagation] = useState(false);
  const [requestStatus, setRequestStatus] = useState<string | null>(
    storedKeys
      ? storedKeys.areKeysPropagated
        ? "Mining keys restored from browser storage."
        : "Mining keys restored from browser storage, waiting re-check."
      : null,
  );
  const [requestError, setRequestError] = useState<string | null>(null);
  const [isRequesting, setIsRequesting] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [initStatus, setInitStatus] = useState<string | null>(null);
  const [initError, setInitError] = useState<string | null>(null);
  const [isMinerRunning, setIsMinerRunning] = useState(false);
  const [canStartMiner, setCanStartMiner] = useState(false);
  const [minerActionError, setMinerActionError] = useState<string | null>(null);
  const [minerDebugInfo, setMinerDebugInfo] = useState<MinerDebugInfo | null>(null);
  const [minerDebugError, setMinerDebugError] = useState<string | null>(null);
  const [isMinerDebugLoading, setIsMinerDebugLoading] = useState(false);
  const propagationTokenRef = useRef(0);

  useEffect(() => {
    minerRef.current = miner;
  }, [miner]);

  useEffect(() => {
    if (!miner) {
      setCanStartMiner(false);
      setIsMinerRunning(false);
      setMinerDebugInfo(null);
      setMinerDebugError(null);
      setIsMinerDebugLoading(false);
      return;
    }

    let cancelled = false;
    const refreshCanStart = () => {
      try {
        const value = miner.can_start();
        if (!cancelled) {
          setCanStartMiner(value);
        }
      } catch {
        if (!cancelled) {
          setCanStartMiner(false);
        }
      }
    };

    refreshCanStart();
    const intervalId = window.setInterval(refreshCanStart, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [miner]);

  useEffect(() => {
    if (!miner) {
      return;
    }

    let cancelled = false;
    let inFlight = false;

    const refreshMinerDebug = async () => {
      if (cancelled || inFlight) {
        return;
      }
      inFlight = true;
      setIsMinerDebugLoading(true);

      try {
        const data = await miner.get_miner_data();
        const nextInfo: MinerDebugInfo = {
          tapSum: data.tap_sum.toString(),
          tapSum5m: data.tap_sum_5m.toString(),
          epochStart: data.epoch_start.toString(),
          epoch5mStart: data.epoch_5m_start.toString(),
          updatedAt: new Date().toLocaleTimeString(),
        };
        data.free();

        if (!cancelled) {
          setMinerDebugInfo(nextInfo);
          setMinerDebugError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setMinerDebugError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        inFlight = false;
        if (!cancelled) {
          setIsMinerDebugLoading(false);
        }
      }
    };

    void refreshMinerDebug();
    const intervalId = window.setInterval(() => {
      void refreshMinerDebug();
    }, MINER_DATA_POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [miner]);

  useEffect(() => {
    return () => {
      propagationTokenRef.current += 1;
      minerRef.current?.free();
    };
  }, []);

  useEffect(() => {
    if (ownerPublic && ownerSecret) {
      writeStoredMiningKeys(connection, {
        ownerPublic,
        ownerSecret,
        minerAddress,
        areKeysPropagated,
      });
      return;
    }

    clearStoredMiningKeys(connection);
  }, [connection, ownerPublic, ownerSecret, minerAddress, areKeysPropagated]);

  const miningKeysStage = requestError
    ? "error"
    : isWaitingKeysPropagation
      ? "waiting"
      : areKeysPropagated
        ? "ready"
        : ownerPublic && ownerSecret
          ? "requested"
          : "empty";

  const miningKeysStageText =
    miningKeysStage === "error"
      ? "error"
      : miningKeysStage === "waiting"
        ? "waiting for propagation"
        : miningKeysStage === "ready"
          ? "ready"
          : miningKeysStage === "requested"
            ? "requested, not propagated yet"
            : "not requested";

  const handleRequestSetMiningKeys = async () => {
    try {
      propagationTokenRef.current += 1;
      setIsRequesting(true);
      setIsWaitingKeysPropagation(false);
      setAreKeysPropagated(false);
      setMinerAddress(null);
      setOwnerPublic(null);
      setOwnerSecret(null);
      clearStoredMiningKeys(connection);
      miner?.free();
      setMiner(undefined);
      setCanStartMiner(false);
      setIsMinerRunning(false);
      setMinerActionError(null);
      setMinerDebugInfo(null);
      setMinerDebugError(null);
      setRequestError(null);
      setRequestStatus(null);
      setInitError(null);
      setInitStatus(null);

      const generated = await gen_mining_keys(APP_ID);
      const beeConnect = new BeeConnect();
      const requestId = crypto.randomUUID();
      const request = await beeConnect.request_set_mining_keys(
        ENDPOINTS,
        connection.sessionId,
        connection.description,
        connection.sessionStateJson,
        APP_ID,
        generated.public,
        30,
        1000,
      );
      // Update session state after re-key
      if (request.updated_session_state_json) {
        connection.sessionStateJson = request.updated_session_state_json;
        writeStoredWalletConnection(connection);
      }

      // Notify push backend (fire-and-forget)
      fetch(`${API_URL}/v1/push/notify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          profile_address: connection.walletAddress,
          kind: "connect_set_mining_keys",
          request_id: requestId,
          origin_name: window.location.hostname,
        }),
      }).catch(() => {});

      setOwnerPublic(generated.public);
      setOwnerSecret(generated.secret);
      setRequestStatus(
        `set_mining_keys requested (${request.message_id ?? "message_id unavailable"}). Waiting for on-chain propagation...`,
      );

      const token = propagationTokenRef.current + 1;
      propagationTokenRef.current = token;
      setIsWaitingKeysPropagation(true);

      void (async () => {
        try {
          const resolvedMinerAddress = await waitForMiningKeysPropagation(
            connection.walletName,
            generated.public,
          );
          if (token !== propagationTokenRef.current) {
            return;
          }
          setMinerAddress(resolvedMinerAddress);
          setAreKeysPropagated(true);
          setRequestStatus(
            "Mining keys propagated and saved in browser storage. You can init miner.",
          );
        } catch (e) {
          if (token !== propagationTokenRef.current) {
            return;
          }
          setRequestStatus(null);
          setRequestError(
            `set_mining_keys propagation failed: ${e instanceof Error ? e.message : String(e)}`,
          );
        } finally {
          if (token === propagationTokenRef.current) {
            setIsWaitingKeysPropagation(false);
          }
        }
      })();
    } catch (e) {
      setRequestError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsRequesting(false);
    }
  };

  const [minerCrashed, setMinerCrashed] = useState(false);

  const handleMinerCallback = (message: string) => {
    minerCallback(message);

    try {
      const payload = JSON.parse(message) as MinerCallbackPayload;
      if (payload.error) {
        setMinerActionError(`${payload.action ?? "miner"}: ${payload.error}`);
        setMinerCrashed(true);
        setIsMinerRunning(false);
      }

      if (payload.action === "status_updated" && payload.data?.status) {
        const status = payload.data.status;
        if (status === "computing" || status === "submitting") {
          setIsMinerRunning(true);
          setMinerCrashed(false);
        }
        if (status === "finished" || status === "removed") {
          setIsMinerRunning(false);
        }
      }
    } catch {
      // Keep callback robust for non-JSON messages.
    }

    try {
      setCanStartMiner(minerRef.current?.can_start() ?? false);
    } catch {
      setCanStartMiner(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", alignItems: "center" }}>
      <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", justifyContent: "center" }}>
        <button
          type="button"
          onClick={handleRequestSetMiningKeys}
          disabled={isRequesting || isWaitingKeysPropagation}
        >
          {isRequesting
            ? "Requesting set_mining_keys..."
            : isWaitingKeysPropagation
              ? "Waiting for on-chain propagation..."
              : "Request set mining keys"}
        </button>
        <button
          type="button"
          disabled={
            !ownerPublic || !ownerSecret || !areKeysPropagated || !minerAddress || isInitializing
          }
          onClick={async () => {
            if (!ownerPublic || !ownerSecret || !minerAddress) {
              return;
            }
            try {
              setIsInitializing(true);
              setInitError(null);
              setInitStatus("Initializing miner...");
              setMinerCrashed(false);
              setMinerActionError(null);
              miner?.free();
              const instance = await initMiner(minerAddress, ownerPublic, ownerSecret);
              setMiner(instance);
              setIsMinerRunning(false);
              setMinerActionError(null);
              setMinerDebugInfo(null);
              setMinerDebugError(null);
              setCanStartMiner(instance.can_start());
              setInitStatus("Miner initialized.");
            } catch (e) {
              setInitStatus(null);
              setInitError(e instanceof Error ? e.message : String(e));
            } finally {
              setIsInitializing(false);
            }
          }}
        >
          {isInitializing ? "Initializing miner..." : "Init miner"}
        </button>
        <button
          type="button"
          disabled={!miner || isInitializing || !canStartMiner || isMinerRunning}
          onClick={async () => {
            if (!miner) {
              return;
            }
            try {
              setMinerActionError(null);
              miner.start(15000, handleMinerCallback);
              setIsMinerRunning(true);
              setCanStartMiner(false);
            } catch (e) {
              setMinerActionError(e instanceof Error ? e.message : String(e));
            }
          }}
        >
          Start miner
        </button>
        <button
          type="button"
          disabled={!miner || isInitializing || !isMinerRunning}
          onClick={() => {
            if (!miner) {
              return;
            }
            try {
              setMinerActionError(null);
              miner.add_tap(1, 1);
            } catch (e) {
              setMinerActionError(e instanceof Error ? e.message : String(e));
            }
          }}
        >
          Add tap
        </button>
        <button
          type="button"
          disabled={!miner || isInitializing || !isMinerRunning}
          onClick={async () => {
            if (!miner) {
              return;
            }
            miner.stop();
            setIsMinerRunning(false);
            setMinerActionError(null);
            try {
              setCanStartMiner(miner.can_start());
            } catch {
              setCanStartMiner(false);
            }
          }}
        >
          Stop miner
        </button>
        <button
          type="button"
          disabled={!miner || isInitializing}
          onClick={async () => {
            if (!miner) {
              return;
            }
            try {
              setMinerActionError(null);
              await miner.get_reward();
            } catch (e) {
              setMinerActionError(e instanceof Error ? e.message : String(e));
            }
          }}
        >
          Get reward
        </button>
      </div>
      <div style={{ color: minerCrashed ? "#e74c3c" : "rgba(255, 255, 255, 0.72)" }}>
        Miner runtime:{" "}
        <strong>
          {minerCrashed ? "crashed — re-init to recover" : isMinerRunning ? "running" : "idle"}
        </strong>{" "}
        | can_start: <strong>{canStartMiner ? "yes" : "no"}</strong>
      </div>
      {miner && (
        <div
          style={{
            width: "min(720px, 92vw)",
            textAlign: "left",
            fontSize: "0.82rem",
            border: "1px solid rgba(255, 255, 255, 0.12)",
            borderRadius: "10px",
            padding: "10px 12px",
            background: "rgba(255, 255, 255, 0.03)",
            color: "rgba(255, 255, 255, 0.8)",
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          }}
        >
          <div style={{ marginBottom: "6px" }}>
            miner.get_miner_data() debug{" "}
            {isMinerDebugLoading
              ? "(updating...)"
              : minerDebugInfo
                ? `(updated ${minerDebugInfo.updatedAt})`
                : ""}
          </div>
          {minerDebugInfo && (
            <div>
              tap_sum={minerDebugInfo.tapSum}, tap_sum_5m={minerDebugInfo.tapSum5m}, epoch_start=
              {minerDebugInfo.epochStart}, epoch_5m_start={minerDebugInfo.epoch5mStart}
            </div>
          )}
          {minerDebugError && (
            <div style={{ color: "rgba(255, 150, 150, 0.95)" }}>
              miner_data poll failed: {minerDebugError}
            </div>
          )}
        </div>
      )}
      <div style={{ color: "rgba(255, 255, 255, 0.72)" }}>
        Mining keys status: <strong>{miningKeysStageText}</strong>
      </div>
      <div style={{ color: "rgba(255, 255, 255, 0.55)" }}>
        Stored in browser: {ownerPublic && ownerSecret ? "yes" : "no"}
      </div>
      {requestStatus && <div style={{ color: "rgba(255, 255, 255, 0.72)" }}>{requestStatus}</div>}
      {requestError && <div style={{ color: "#e74c3c" }}>{requestError}</div>}
      {initStatus && <div style={{ color: "rgba(255, 255, 255, 0.72)" }}>{initStatus}</div>}
      {initError && <div style={{ color: "#e74c3c" }}>{initError}</div>}
      {minerActionError && <div style={{ color: "#e74c3c" }}>{minerActionError}</div>}
      {!ownerPublic && (
        <div style={{ color: "rgba(255, 255, 255, 0.72)" }}>
          First request mining keys via connect protocol.
        </div>
      )}
    </div>
  );
}

function App() {
  const [walletConnection, setWalletConnection] = useState<WalletConnection | null>(() =>
    readStoredWalletConnection(),
  );
  const [isWasmLoading, setIsWasmLoading] = useState(true);
  const [isWasmReady, setIsWasmReady] = useState(false);
  const [wasmError, setWasmError] = useState<string | null>(null);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [sessionMonitorError, setSessionMonitorError] = useState<string | null>(null);
  const [isSessionPolling, setIsSessionPolling] = useState(false);
  const [nacklBalance, setNacklBalance] = useState<string | null>(null);
  const [nacklBalanceError, setNacklBalanceError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        setIsWasmLoading(true);
        setWasmError(null);
        await initBeeSdk();
        if (!mounted) {
          return;
        }
        setIsWasmReady(true);
      } catch (e) {
        if (!mounted) {
          return;
        }
        setWasmError(e instanceof Error ? e.message : String(e));
      } finally {
        if (mounted) {
          setIsWasmLoading(false);
        }
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    writeStoredWalletConnection(walletConnection);
  }, [walletConnection]);

  useEffect(() => {
    if (!isWasmReady || !walletConnection) {
      setIsSessionPolling(false);
      return;
    }

    let cancelled = false;
    let inFlight = false;

    const checkSession = async () => {
      if (cancelled || inFlight) {
        return;
      }
      inFlight = true;
      setIsSessionPolling(true);

      try {
        const exists = await isSessionStillActive(walletConnection);
        if (cancelled) {
          return;
        }

        if (!exists) {
          console.error(
            "[SESSION_MONITOR] session inactive — dropping connection. wallet:",
            walletConnection.walletName,
            "profile:",
            walletConnection.profileAddress,
          );
          clearStoredMiningKeys(walletConnection);
          setSessionMonitorError("Wallet disconnected the session. Please reconnect.");
          setWalletConnection(null);
          return;
        }

        setSessionMonitorError(null);
      } catch (e) {
        if (!cancelled) {
          setSessionMonitorError(
            `Session monitor failed: ${e instanceof Error ? e.message : String(e)}`,
          );
        }
      } finally {
        if (!cancelled) {
          setIsSessionPolling(false);
        }
        inFlight = false;
      }
    };

    void checkSession();
    const intervalId = window.setInterval(() => {
      void checkSession();
    }, SESSION_POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [isWasmReady, walletConnection]);

  useEffect(() => {
    if (!isWasmReady || !walletConnection) {
      setNacklBalance(null);
      setNacklBalanceError(null);
      return;
    }

    let cancelled = false;
    let inFlight = false;
    const wallet = new Wallet(ENDPOINTS, null, API_URL, APP_ID);

    const pollBalance = async () => {
      if (cancelled || inFlight) {
        return;
      }
      inFlight = true;

      try {
        const nativeBalances = await wallet.get_multifactor_balances({
          multifactor_address: walletConnection.walletAddress,
        });
        if (cancelled) {
          return;
        }

        const token1 = nativeBalances.ecc["1"] ?? "0";
        setNacklBalance(formatNanoToDisplay(token1, 9, 4));
        setNacklBalanceError(null);
      } catch (e) {
        if (!cancelled) {
          setNacklBalanceError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        inFlight = false;
      }
    };

    void pollBalance();
    const intervalId = window.setInterval(() => {
      void pollBalance();
    }, BALANCE_POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      wallet.free();
    };
  }, [isWasmReady, walletConnection]);

  const handleDisconnect = async () => {
    if (!walletConnection) {
      return;
    }

    try {
      console.log("[DISCONNECT] user requested disconnect");
      setIsDisconnecting(true);
      setDisconnectError(null);

      const beeConnect = new BeeConnect();
      await beeConnect.disconnect_session(
        ENDPOINTS,
        walletConnection.sessionId,
        walletConnection.description,
        walletConnection.sessionStateJson,
        "user_requested",
        30,
        1000,
      );

      clearStoredMiningKeys(walletConnection);
      setSessionMonitorError(null);
      setNacklBalance(null);
      setNacklBalanceError(null);
      setWalletConnection(null);
    } catch (e) {
      setDisconnectError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsDisconnecting(false);
    }
  };

  return (
    <>
      <div className="logo-shell">
        <img src={Logo} className="logo logo-spin" alt="Nackl logo" />
      </div>
      <h1>Acki-connect demo</h1>
      <p style={{ color: "#888", fontSize: "0.85em", margin: "-8px 0 12px" }}>Network: shellnet</p>

      {isWasmLoading && <div>Loading wasm...</div>}

      {!isWasmLoading && wasmError && (
        <div style={{ color: "#e74c3c" }}>Failed to init wasm: {wasmError}</div>
      )}
      {sessionMonitorError && (
        <div
          style={{
            color: "rgba(255, 196, 110, 0.95)",
            background: "rgba(255, 196, 110, 0.08)",
            border: "1px solid rgba(255, 196, 110, 0.25)",
            borderRadius: "10px",
            padding: "12px 16px",
            marginBottom: "12px",
          }}
        >
          {sessionMonitorError}
        </div>
      )}

      {!isWasmLoading && isWasmReady && !walletConnection ? (
        <WalletConnect
          onConnected={(connection) => {
            setSessionMonitorError(null);
            setWalletConnection(connection);
          }}
        />
      ) : (
        walletConnection && (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div>
              Connected wallet: <strong>{walletConnection.walletName}</strong>{" "}
              <span style={{ color: "rgba(255, 255, 255, 0.78)" }}>
                (NACKL: {nacklBalance ?? "..."})
              </span>
              {walletConnection.inlineChallenge && (
                <span style={{ color: "#2ecc71", marginLeft: "8px" }}>verified at connect</span>
              )}
            </div>
            {walletConnection.inlineChallenge && (
              <div
                style={{
                  fontSize: "0.8rem",
                  color: "rgba(255, 255, 255, 0.55)",
                  wordBreak: "break-all",
                }}
              >
                <div>nonce: {walletConnection.inlineChallenge.nonce}</div>
                <div>signature: {walletConnection.inlineChallenge.signature}</div>
                <div>epk: {walletConnection.inlineChallenge.epkPublic}</div>
              </div>
            )}
            {nacklBalanceError && (
              <div style={{ color: "rgba(255, 196, 110, 0.9)" }}>
                NACKL polling warning: {nacklBalanceError}
              </div>
            )}
            <div style={{ color: "rgba(255, 255, 255, 0.72)" }}>
              Session monitor: {isSessionPolling ? "checking..." : "active"}
            </div>

            <div style={{ display: "flex", justifyContent: "center" }}>
              <button type="button" onClick={handleDisconnect} disabled={isDisconnecting}>
                {isDisconnecting ? "Disconnecting..." : "Disconnect"}
              </button>
            </div>
            {disconnectError && <div style={{ color: "#e74c3c" }}>{disconnectError}</div>}
            <VerifyWalletPanel
              connection={walletConnection}
              onSessionDesync={() => {
                console.error("[APP] onSessionDesync fired — dropping connection");
                clearStoredMiningKeys(walletConnection);
                setWalletConnection(null);
              }}
            />
            <MinerPanel key={walletConnection.profileAddress} connection={walletConnection} />
          </div>
        )
      )}
    </>
  );
}

export default App;
