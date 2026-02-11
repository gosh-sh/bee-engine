import viteLogo from "/vite.svg";
import reactLogo from "./assets/react.svg";
import "./App.css";

import { init, Miner } from "@bee-engine/miner";
import { useState } from "react";

async function initMiner() {
  await init({ module_or_path: "/bee_engine_miner_bg.wasm" });
  return await Miner.new(
    ["localhost"],
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0:07226468b64d2745a7857fb745a2b4a3974f7bcce30b29d23b231587231e47a3",
    "",
    "",
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
