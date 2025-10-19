const CONTRACTS = {
  NEURA: {
    SWAP_ROUTER: "0x5AeFBA317BAba46EAF98Fd6f381d07673bcA6467",
    WANKR: "0xbd833b6ecc30caeabf81db18bb0f1e00c6997e7a",
    ZTUSD: "0x9423c6c914857e6daaace3b585f4640231505128",
    BRIDGE: "0xc6255a594299F1776de376d0509aB5ab875A6E3E",
    OMNIHUB_NFT: "0x6f38636175e178e1d2004431ffcb91a1030282ac", // OmniHub NFT Contract
  },
  SEPOLIA: {
    BRIDGE: "0xc6255a594299F1776de376d0509aB5ab875A6E3E",
    TANKR: "0xB88Ca91Fef0874828e5ea830402e9089aaE0bB7F",
  },
};

const ABIS = {
  SWAP_ROUTER: ["function multicall(bytes[] data) payable returns (bytes[] results)"],
  ERC20: [
    "function approve(address spender, uint256 amount) external returns (bool)",
    "function balanceOf(address account) external view returns (uint256)",
    "function allowance(address owner, address spender) external view returns (uint256)",
    "function decimals() external view returns (uint8)",
    "function transfer(address to, uint256 amount) external returns (bool)",
  ],
  NEURA_BRIDGE: ["function deposit(address _recipient, uint256 _chainId) payable"],
  SEPOLIA_BRIDGE: ["function deposit(uint256 assets, address receiver) external"],
  BRIDGE_CLAIM: ["function claim(bytes encodedMessage, bytes[] messageSignatures) external"],
  OMNIHUB_NFT: [
    "function mintNFT(uint256 phaseId, uint256 quantity, uint256 paymentToken, bytes memory data) payable",
    "function phases(uint256) view returns (string memory name, uint256 startTime, uint256 endTime, uint256 maxSupply, uint256 mintedSupply, uint256 maxPerWallet)",
    "function getMintPrice(uint256 phaseId, uint256 quantity) view returns (uint256)",
    "function balanceOf(address owner) view returns (uint256)",
    "function tokenOfOwnerByIndex(address owner, uint256 index) view returns (uint256)",
  ],
};

module.exports = { CONTRACTS, ABIS };
