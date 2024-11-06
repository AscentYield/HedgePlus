// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/IHedgePlusDefinitions.sol";

/**
 * @title HedgePlus
 * @notice HedgePlus
 */
contract HedgePlus is Ownable2Step, ERC20Burnable, ERC20Permit, IHedgePlusDefinitions {
  address public minter;

  constructor(address admin) ERC20("HedgePlus", "HedgePlus") ERC20Permit("HedgePlus") {
    if (admin == address(0)) revert ZeroAddressException();
    _transferOwnership(admin);
  }

  function setMinter(address newMinter) external onlyOwner {
    emit MinterUpdated(newMinter, minter);
    minter = newMinter;
  }

  function mint(address to, uint256 amount) external {
    if (msg.sender != minter) revert OnlyMinter();
    _mint(to, amount);
  }

  function renounceOwnership() public view override onlyOwner {
    revert CantRenounceOwnership();
  }
}
