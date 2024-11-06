// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

/* solhint-disable var-name-mixedcase  */

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/IRedeemSiloDefinitions.sol";

/**
 * @title RedeemSilo
 * @notice The Silo allows to store assets during the redeem cooldown process.
 */
contract RedeemSilo is IRedeemSiloDefinitions {
  using SafeERC20 for IERC20;
  address immutable _MINTING_CONTRACT;

  constructor(address mintingContract) {
    _MINTING_CONTRACT = mintingContract;
  }

  modifier onlyMintingContract() {
    if (msg.sender != _MINTING_CONTRACT) revert OnlyMintingContract();
    _;
  }

  function withdraw(address asset, address to, uint256 amount) external onlyMintingContract {
    IERC20(asset).safeTransfer(to, amount);
  }
}
