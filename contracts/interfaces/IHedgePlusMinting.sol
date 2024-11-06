// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/* solhint-disable var-name-mixedcase  */

import "./IHedgePlusMintingEvents.sol";

interface IHedgePlusMinting is IHedgePlusMintingEvents {
  enum Role {
    Minter,
    Redeemer
  }

  enum OrderType {
    MINT,
    REDEEM
  }

  enum SignatureType {EIP712}

  enum DelegatedSignerStatus {
    REJECTED,
    PENDING,
    ACCEPTED
  }

  struct Signature {
    SignatureType signature_type;
    bytes signature_bytes;
  }

  struct Route {
    address[] addresses;
    uint256[] ratios;
  }

  struct Order {
    OrderType order_type;
    uint256 expiry;
    uint256 nonce;
    address benefactor;
    address beneficiary;
    address collateral_asset;
    uint256 collateral_amount;
    uint256 hedgeplus_amount;
  }

  struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
  }

  error InvalidAddress();
  error InvalidHedgePlusAddress();
  error InvalidZeroAddress();
  error InvalidAssetAddress();
  error InvalidCustodianAddress();
  error InvalidOrder();
  error InvalidFeeManager();
  error InvalidAmount();
  error InvalidRoute();
  error UnsupportedAsset();
  error NoAssetsProvided();
  error InvalidSignature();
  error InvalidNonce();
  error SignatureExpired();
  error TransferFailed();
  error MaxMintPerBlockExceeded();
  error MaxRedeemPerBlockExceeded();
  error DelegationNotInitiated();
  error InvalidCooldown();

  function hashOrder(Order calldata order) external view returns (bytes32);

  function verifyOrder(Order calldata order, Signature calldata signature) external view returns (bytes32);

  function verifyRoute(Route calldata route) external view returns (bool);

  function verifyNonce(address sender, uint256 nonce) external view returns (uint256, uint256, uint256);

  function chargeManagementFee(address manager, uint256 amount) external;

  function mint(Order calldata order, Route calldata route, Signature calldata signature) external;

  function redeem(Order calldata order, Signature calldata signature) external;

  function settleRedeemOrders(Order[] calldata orders) external;

  function setCooldownDuration(uint24 duration) external;
}
