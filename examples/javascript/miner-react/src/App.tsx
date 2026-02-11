import viteLogo from "/vite.svg";
import reactLogo from "./assets/react.svg";
import "./App.css";

import {
  ensure_mining_keys_propagated,
  gen_mining_keys,
  get_miner_address_by_wallet_name,
  init,
  Miner,
} from "bee-sdk";
import { useState } from "react";

const APP_ID = "0x0000000000000000000000000000000000000000000000000000000000000000";
const WALLET_NAME = "demo_wallet";
const ENDPOINTS = ["mainnet.ackinacki.org"];

async function initMiner() {
  await init({ module_or_path: "/bee_engine_miner_bg.wasm" });
  const resultOfGenKeys = await gen_mining_keys(APP_ID);
  const minerAddress = await get_miner_address_by_wallet_name({
    client_config: {
      network: {
        endpoints: ENDPOINTS,
      },
    },
    wallet_name: WALLET_NAME,
  });

  await ensure_mining_keys_propagated({
    client_config: {
      network: {
        endpoints: ENDPOINTS,
      },
    },
    miner_address: minerAddress,
    app_id: APP_ID,
    expected_owner_public: resultOfGenKeys.public,
    max_attempts: 30,
    interval_ms: 1000,
  });

  return await Miner.new(
    ENDPOINTS,
    APP_ID,
    minerAddress,
    resultOfGenKeys.public,
    resultOfGenKeys.secret,
  );
}

function minerCallback(message: string) {
  console.log(`[MINER_CALLBACK]: ${message}`);
}

function App() {
  const [miner, setMiner] = useState<Miner>();

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank" rel="noreferrer">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank" rel="noreferrer">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>

      <div style={{ display: "flex", gap: "16px" }}>
        <button
          type="button"
          onClick={async () => {
            miner?.free();

            const instance = await initMiner();
            setMiner(instance);
          }}
        >
          Init miner
        </button>
        <button type="button" onClick={() => miner?.start(15000, minerCallback)}>
          Start miner
        </button>
        <button type="button" onClick={() => miner?.add_tap(1, 1)}>
          Add tap
        </button>
        <button type="button" onClick={() => miner?.stop()}>
          Stop miner
        </button>
      </div>
    </>
  );
}

export default App;
