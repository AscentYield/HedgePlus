Here's a restructured version with the same content but different organization and wording:

# Protocol Overview & Documentation

## Contents
- Scope of Audit
- Core Protocol Overview
- Technical Documentation
- Contract Architecture
- Security & Access Control

## Audit Coverage
The audit scope includes contracts in the /contracts directory:
- `HedgePlus.sol`
- `HedgePlusMintingUpgradeable.sol` (including its extensions and derived contracts)

For comprehensive protocol documentation, visit: https://docs.ascentyield.io/

## Core Contract Architecture

### HedgePlus Token Contract
The `HedgePlus.sol` implements our stablecoin, built on OpenZeppelin's `ERC20Burnable`, `ERC20Permit`, and `Ownable2Step`. It features a single configurable `minter` address that can be updated by the owner. This minter address (assigned to `HedgePlusMintingUpgradeable.sol`) holds exclusive minting privileges.

### Minting & Redemption Contract
`HedgePlusMintingUpgradeable.sol` serves as the protocol's core operational contract, managing token minting and redemption processes.

## Key Operations

### Minting Process
The `mint()` function processes user minting requests using:
- User-signed EIP712 orders
- Signature verification
- Route parameters (defined by Ascent Yield)
All fund routes must use verified custodian addresses (`_custodianAddresses`), manageable only by `DEFAULT_ADMIN_ROLE`.

### Redemption Mechanism
Users initiate redemptions via EIP712 signatures with Ascent Yield-provided prices. Upon submission to the `redeem()` function, tokens are held in contract until the UTC 00:00 settlement.

### Settlement Process
The `settleRedeemOrders()` processes backend-provided orders at UTC 00:00, transferring USDC to redeemSilo. Users can withdraw via `claim()` after a 7-day cooldown.

### Claims
The `claim()` function enables USDC withdrawals from redeemSilo following the cooldown period.

## Signature Delegation System
For smart contract interactions, the protocol supports delegated signers through:
- `setDelegatedSigner`: Assigns signing privileges
- `removeDelegatedSigner`: Revokes delegation
- Multiple concurrent delegations supported
- Compatible with both contracts and EOAs

## Security Architecture
The protocol implements role-based access control, with critical functions (minting, redemption) managed via signature server. Full security details: https://docs.ascentyield.io/yield-market/solutions/fund-security