const CHAINS = [
  "Ethereum", "BSC", "Polygon", "Arbitrum", "Optimism", "Base", "Avalanche",
  "Linea", "Scroll", "Mantle", "Blast", "Mode", "Starknet",
  "Solana", "Osmosis", "Injective", "Neutron", "TRON",
  "Aptos", "Sui", "NEAR", "TON", "Bitcoin",
];

export default function ChainMarquee() {
  const row = [...CHAINS, ...CHAINS]; // double for seamless loop
  return (
    <div className="marquee">
      <div className="marquee-track">
        {row.map((c, i) => (
          <span key={`${c}-${i}`} className="marquee-item">
            <span className="dot" />
            <span>{c}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
