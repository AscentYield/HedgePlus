// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

import "./SingleAdminAccessControlUpgradeable.sol";
import "./interfaces/IHedgePlus.sol";
import "./interfaces/IHedgePlusMinting.sol";
import "./RedeemSilo.sol";


/**
 * @title HedgePlus Minting
 * @notice This contract mints and redeems HedgePlus
 */
contract HedgePlusMinting is 
    Initializable, 
    UUPSUpgradeable, 
    SingleAdminAccessControlUpgradeable, 
    ReentrancyGuardUpgradeable,
    IHedgePlusMinting 
{

  using SafeERC20Upgradeable for IERC20Upgradeable;
  using ECDSAUpgradeable for bytes32;
  using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

  /* --------------- CONSTANTS --------------- */

  /// @notice EIP712 domain
  bytes32 private constant EIP712_DOMAIN =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  /// @notice route type
  bytes32 private constant ROUTE_TYPE = keccak256("Route(address[] addresses,uint256[] ratios)");

  /// @notice order type
  bytes32 private constant ORDER_TYPE = keccak256(
    "Order(uint8 OrderType,uint256 Expiry,uint256 Nonce,address Benefactor,address Beneficiary,address CollateralAsset,uint256 CollateralAmount,uint256 HedgeplusAmount)"
  );

  /// @notice role enabling to invoke mint
  bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");

  /// @notice role enabling to invoke redeem
  bytes32 private constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE");

  /// @notice role enabling to be sent management fees
  bytes32 private constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");

  /// @notice role enabling to transfer collateral to custody wallets
  bytes32 private constant COLLATERAL_MANAGER_ROLE = keccak256("COLLATERAL_MANAGER_ROLE");

  /// @notice role enabling to disable mint and redeem and remove minters and redeemers in an emergency
  bytes32 private constant GATEKEEPER_ROLE = keccak256("GATEKEEPER_ROLE");

  /// @notice role which prevents an address to claim in an emergency
  bytes32 private constant RESTRICTED_CLAIM_ROLE = keccak256("RESTRICTED_CLAIM_ROLE");

  /// @notice EIP712 domain hash
  bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));

  /// @notice address denoting native ether
  address private constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

  /// @notice EIP712 name
  bytes32 private constant EIP_712_NAME = keccak256("HedgePlusMinting");

  /// @notice holds EIP712 revision
  bytes32 private constant EIP712_REVISION = keccak256("1");

  /// @notice required ratio for route
  uint256 private constant ROUTE_REQUIRED_RATIO = 10_000;

  /* --------------- STATE VARIABLES --------------- */

  /// @notice HedgePlus token
  IHedgePlus public hedgeplus;

  /// @notice Supported assets
  EnumerableSetUpgradeable.AddressSet internal _supportedAssets;

  // @notice custodian addresses
  EnumerableSetUpgradeable.AddressSet internal _custodianAddresses;

  /// @notice holds computable chain id
  uint256 private _chainId;

  /// @notice holds computable domain separator
  bytes32 private _domainSeparator;

  /// @notice user deduplication
  mapping(address => mapping(uint256 => uint256)) private _orderBitmaps;

  /// @notice HedgePlus minted per block
  mapping(uint256 => uint256) public mintedPerBlock;
  /// @notice HedgePlus redeemed per block
  mapping(uint256 => uint256) public redeemedPerBlock;

  /// @notice For smart contracts to delegate signing to EOA address
  mapping(address => mapping(address => DelegatedSignerStatus)) public delegatedSigner;

  /// @notice max minted HedgePlus allowed per block
  uint256 public maxMintPerBlock;
  /// @notice max redeemed HedgePlus allowed per block
  uint256 public maxRedeemPerBlock;

  /// @notice redeem silo
  RedeemSilo public redeemSilo;

  /// @notice redeem cooldown duration
  uint24 public constant MAX_COOLDOWN_DURATION = 7 days;

  uint24 public cooldownDuration;

  mapping(address => mapping(address => UserCooldown)) public cooldowns;

  bool private _initialized;

  /* --------------- MODIFIERS --------------- */

  /// @notice ensure that the already minted HedgePlus in the actual block plus the amount to be minted is below the maxMintPerBlock var
  /// @param mintAmount The HedgePlus amount to be minted
  modifier belowMaxMintPerBlock(uint256 mintAmount) {
    if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();
    _;
  }

  /// @notice ensure that the already redeemed HedgePlus in the actual block plus the amount to be redeemed is below the maxRedeemPerBlock var
  /// @param redeemAmount The HedgePlus amount to be redeemed
  modifier belowMaxRedeemPerBlock(uint256 redeemAmount) {
    if (redeemedPerBlock[block.number] + redeemAmount > maxRedeemPerBlock) revert MaxRedeemPerBlockExceeded();
    _;
  }

  /* --------------- CONSTRUCTOR --------------- */

  constructor() {
    _disableInitializers();
  }

  function initialize(
    IHedgePlus _hedgeplus,
    address[] memory _assets,
    address[] memory _custodians,
    address _admin,
    uint256 _maxMintPerBlock,
    uint256 _maxRedeemPerBlock
  ) public initializer {
    __SingleAdminAccessControl_init(_admin);
    __ReentrancyGuard_init();
    __UUPSUpgradeable_init();

    if (!_initialized) {
      if (address(_hedgeplus) == address(0)) revert InvalidHedgePlusAddress();
      if (_assets.length == 0) revert NoAssetsProvided();
      if (_admin == address(0)) revert InvalidZeroAddress();
      redeemSilo = new RedeemSilo(address(this));
      hedgeplus = _hedgeplus;
      cooldownDuration = MAX_COOLDOWN_DURATION;
      _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
      for (uint256 i = 0; i < _assets.length;) {
        addSupportedAsset(_assets[i]);
        unchecked { ++i; }
      }

      for (uint256 j = 0; j < _custodians.length;) {
        addCustodianAddress(_custodians[j]);
        unchecked { ++j; }
      }
      _setMaxMintPerBlock(_maxMintPerBlock);
      _setMaxRedeemPerBlock(_maxRedeemPerBlock);

      _chainId = block.chainid;
      _domainSeparator = _computeDomainSeparator();
      emit HedgePlusSet(address(_hedgeplus));
      _initialized = true;
    }
  }

  /* --------------- EXTERNAL --------------- */

  /**
   * @notice Fallback function to receive ether
   */
  receive() external payable {
    emit Received(msg.sender, msg.value);
  }

  /**
   * @notice Mint HedgePlus from assets
   * @param order struct containing order details and confirmation from server
   * @param signature signature of the taker
   */
  function mint(Order calldata order, Route calldata route, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(MINTER_ROLE)
    belowMaxMintPerBlock(order.hedgeplus_amount)
  {
    if (order.order_type != OrderType.MINT) revert InvalidOrder();
    verifyOrder(order, signature);
    if (!verifyRoute(route)) revert InvalidRoute();
    _deduplicateOrder(order.benefactor, order.nonce);
    // Add to the minted amount in this block
    mintedPerBlock[block.number] += order.hedgeplus_amount;
    _transferCollateral(
      order.collateral_amount, order.collateral_asset, order.benefactor, route.addresses, route.ratios
    );
    hedgeplus.mint(order.beneficiary, order.hedgeplus_amount);
    emit Mint(
      msg.sender,
      order.benefactor,
      order.beneficiary,
      order.collateral_asset,
      order.collateral_amount,
      order.hedgeplus_amount
    );
  }
  
  /**
   * @notice Redeem HedgePlus for assets
   * @param order struct containing order details and confirmation from server
   * @param signature signature of the taker
   */
  function redeem(Order calldata order, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
    belowMaxRedeemPerBlock(order.hedgeplus_amount)
  {
    if (order.order_type != OrderType.REDEEM) revert InvalidOrder();
    verifyOrder(order, signature);
    _deduplicateOrder(order.benefactor, order.nonce);
    // Add to the redeemed amount in this block
    redeemedPerBlock[block.number] += order.hedgeplus_amount;

    // Add to the cooldown
    cooldowns[order.beneficiary][order.collateral_asset].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[order.beneficiary][order.collateral_asset].underlyingAmount += uint152(0);

    // tranfer HedgePlus from the benefactor to this contract, lock the HedgePlus
    hedgeplus.transferFrom(order.benefactor, address(this), order.hedgeplus_amount);
    emit Redeem(
      msg.sender,
      order.benefactor,
      order.beneficiary,
      order.collateral_asset,
      order.collateral_amount,
      order.hedgeplus_amount
    );
  }

  /**
   * @notice Settle HedgePlus redeem order
   * @param orders is order struct array
   */
  function settleRedeemOrders(Order[] calldata orders)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
  {
    uint256 totalCollateralAmount = 0;
    uint256 totalHedgePlusAmount = 0;
    address assetAddress = orders[0].collateral_asset;
    /// calculate total collateral and HedgePlus amount
    for (uint256 i = 0; i < orders.length; i++) {
      Order memory order = orders[i];
      if (order.order_type != OrderType.REDEEM) revert InvalidOrder();
      totalCollateralAmount += order.collateral_amount;
      totalHedgePlusAmount += order.hedgeplus_amount;
      cooldowns[order.beneficiary][order.collateral_asset].underlyingAmount += uint152(order.collateral_amount);
    }

    if (totalHedgePlusAmount == 0 || totalCollateralAmount == 0) revert InvalidAmount();
    hedgeplus.burn(totalHedgePlusAmount);
    _transferToRedeemSilo(assetAddress, totalCollateralAmount);
    emit RedeemSettle(
      msg.sender,
      assetAddress,
      totalCollateralAmount,
      totalHedgePlusAmount
    );
  }

  /// @notice Set cooldown duration.
  /// @param duration Duration of the cooldown
  function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) {
      revert InvalidCooldown();
    }

    uint24 previousDuration = cooldownDuration;
    cooldownDuration = duration;
    emit CooldownDurationUpdated(previousDuration, cooldownDuration);
  }

  /// @notice Claim the redeem amount asset after the cooldown has finished. The address can only retire the full amount of assets.
  /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
  /// @param receiver Address to send the assets
  function claim(address receiver, address asset) external {
    if(hasRole(RESTRICTED_CLAIM_ROLE, receiver)){
      revert InvalidAddress();
    }
    UserCooldown storage userCooldown = cooldowns[msg.sender][asset];
    uint152 amount = userCooldown.underlyingAmount;
    if (amount == 0) revert InvalidAmount();
    if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
      userCooldown.cooldownEnd = 0;
      userCooldown.underlyingAmount = 0;

      redeemSilo.withdraw(asset, receiver, amount);
    } else {
      revert InvalidCooldown();
    }
  }

  /**
   * @notice Charge management fee
   * @param amount The hedgeplus amount to be charged
   */
  function chargeManagementFee(address manager, uint256 amount)
    external
    override
    nonReentrant
    onlyRole(DEFAULT_ADMIN_ROLE)
    belowMaxMintPerBlock(amount)
  {
    if (!hasRole(FEE_MANAGER_ROLE, manager)) revert InvalidFeeManager();
    mintedPerBlock[block.number] += amount;
    hedgeplus.mint(manager, amount);
    emit ChargeManagementFee(
      manager,
      amount
    );
  }

  /// @notice Sets the max mintPerBlock limit
  function setMaxMintPerBlock(uint256 _maxMintPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _setMaxMintPerBlock(_maxMintPerBlock);
  }

  /// @notice Sets the max redeemPerBlock limit
  function setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _setMaxRedeemPerBlock(_maxRedeemPerBlock);
  }

  /// @notice Disables the mint and redeem
  function disableMintRedeem() external onlyRole(GATEKEEPER_ROLE) {
    _setMaxMintPerBlock(0);
    _setMaxRedeemPerBlock(0);
  }

  /// @notice Enables smart contracts to delegate an address for signing
  function setDelegatedSigner(address _delegateTo) external {
    delegatedSigner[_delegateTo][msg.sender] = DelegatedSignerStatus.PENDING;
    emit DelegatedSignerInitiated(_delegateTo, msg.sender);
  }

  /// @notice The delegated address to confirm delegation
  function confirmDelegatedSigner(address _delegatedBy) external {
    if (delegatedSigner[msg.sender][_delegatedBy] != DelegatedSignerStatus.PENDING) {
      revert DelegationNotInitiated();
    }
    delegatedSigner[msg.sender][_delegatedBy] = DelegatedSignerStatus.ACCEPTED;
    emit DelegatedSignerAdded(msg.sender, _delegatedBy);
  }

  /// @notice Enables smart contracts to undelegate an address for signing
  function removeDelegatedSigner(address _removedSigner) external {
    delegatedSigner[_removedSigner][msg.sender] = DelegatedSignerStatus.REJECTED;
    emit DelegatedSignerRemoved(_removedSigner, msg.sender);
  }

  /// @notice transfers an asset to a custody wallet
  function transferToCustody(address wallet, address asset, uint256 amount)
    external
    nonReentrant
    onlyRole(COLLATERAL_MANAGER_ROLE)
  {
    if (wallet == address(0) || !_custodianAddresses.contains(wallet)) revert InvalidAddress();
    if (asset == NATIVE_TOKEN) {
      (bool success,) = wallet.call{value: amount}("");
      if (!success) revert TransferFailed();
    } else {
      IERC20Upgradeable(asset).safeTransfer(wallet, amount);
    }
    emit CustodyTransfer(wallet, asset, amount);
  }

  /// @notice Rescue asset from redeemSilo if emergency
  function rescueRedeemSiloAsset(address asset, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (!_supportedAssets.remove(asset)) revert InvalidAssetAddress();
    redeemSilo.withdraw(asset, address(this), amount);
  }

  /// @notice Removes an asset from the supported assets list
  function removeSupportedAsset(address asset) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (!_supportedAssets.remove(asset)) revert InvalidAssetAddress();
    emit AssetRemoved(asset);
  }

  /// @notice Checks if an asset is supported.
  function isSupportedAsset(address asset) external view returns (bool) {
    return _supportedAssets.contains(asset);
  }

  /// @notice Removes an custodian from the custodian address list
  function removeCustodianAddress(address custodian) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (!_custodianAddresses.remove(custodian)) revert InvalidCustodianAddress();
    emit CustodianAddressRemoved(custodian);
  }

  /// @notice Removes the minter role from an account, this can ONLY be executed by the gatekeeper role
  /// @param minter The address to remove the minter role from
  function removeMinterRole(address minter) external onlyRole(GATEKEEPER_ROLE) {
    _revokeRole(MINTER_ROLE, minter);
  }

  /// @notice Removes the redeemer role from an account, this can ONLY be executed by the gatekeeper role
  /// @param redeemer The address to remove the redeemer role from
  function removeRedeemerRole(address redeemer) external onlyRole(GATEKEEPER_ROLE) {
    _revokeRole(REDEEMER_ROLE, redeemer);
  }

  /// @notice Removes the collateral manager role from an account, this can ONLY be executed by the gatekeeper role
  /// @param collateralManager The address to remove the collateralManager role from
  function removeCollateralManagerRole(address collateralManager) external onlyRole(GATEKEEPER_ROLE) {
    _revokeRole(COLLATERAL_MANAGER_ROLE, collateralManager);
  }

  /* --------------- PUBLIC --------------- */

  /// @notice Adds an asset to the supported assets list.
  function addSupportedAsset(address asset) public onlyRole(DEFAULT_ADMIN_ROLE) {
    if (asset == address(0) || asset == address(hedgeplus) || !_supportedAssets.add(asset)) {
      revert InvalidAssetAddress();
    }
    emit AssetAdded(asset);
  }

  /// @notice Adds an custodian to the supported custodians list.
  function addCustodianAddress(address custodian) public onlyRole(DEFAULT_ADMIN_ROLE) {
    if (custodian == address(0) || custodian == address(hedgeplus) || !_custodianAddresses.add(custodian)) {
      revert InvalidCustodianAddress();
    }
    emit CustodianAddressAdded(custodian);
  }

  /// @notice Get the domain separator for the token
  /// @dev Return cached value if chainId matches cache, otherwise recomputes separator, to prevent replay attack across forks
  /// @return The domain separator of the token at current chain
  function getDomainSeparator() public view returns (bytes32) {
    if (block.chainid == _chainId) {
      return _domainSeparator;
    }
    return _computeDomainSeparator();
  }

  /// @notice hash an Order struct
  function hashOrder(Order calldata order) public view override returns (bytes32) {
    return ECDSAUpgradeable.toTypedDataHash(getDomainSeparator(), keccak256(encodeOrder(order)));
  }

  function encodeOrder(Order calldata order) public pure returns (bytes memory) {
    return abi.encode(
      ORDER_TYPE,
      order.order_type,
      order.expiry,
      order.nonce,
      order.benefactor,
      order.beneficiary,
      order.collateral_asset,
      order.collateral_amount,
      order.hedgeplus_amount
    );
  }

  /// @notice assert validity of signed order
  function verifyOrder(Order calldata order, Signature calldata signature)
    public
    view
    override
    returns (bytes32 taker_order_hash)
  {
    taker_order_hash = hashOrder(order);
    address signer = ECDSAUpgradeable.recover(taker_order_hash, signature.signature_bytes);
    if (!(signer == order.benefactor || delegatedSigner[signer][order.benefactor] == DelegatedSignerStatus.ACCEPTED)) {
      revert InvalidSignature();
    }
    if (order.beneficiary == address(0)) revert InvalidAddress();
    if (order.collateral_amount == 0 && order.order_type == OrderType.MINT) revert InvalidAmount();
    if (order.hedgeplus_amount == 0) revert InvalidAmount();
    if (block.timestamp > order.expiry) revert SignatureExpired();
  }

  /// @notice assert validity of route object per type
  function verifyRoute(Route calldata route) public view override returns (bool) {
    uint256 totalRatio = 0;
    if (route.addresses.length != route.ratios.length) {
      return false;
    }
    if (route.addresses.length == 0) {
      return false;
    }
    for (uint256 i = 0; i < route.addresses.length;) {
      if (!_custodianAddresses.contains(route.addresses[i]) || route.addresses[i] == address(0) || route.ratios[i] == 0)
      {
        return false;
      }
      totalRatio += route.ratios[i];
      unchecked {
        ++i;
      }
    }
    return (totalRatio == ROUTE_REQUIRED_RATIO);
  }

  /// @notice verify validity of nonce by checking its presence
  function verifyNonce(address sender, uint256 nonce) public view override returns (uint256, uint256, uint256) {
    if (nonce == 0) revert InvalidNonce();
    uint256 invalidatorSlot = uint64(nonce) >> 8;
    uint256 invalidatorBit = 1 << uint8(nonce);
    uint256 invalidator = _orderBitmaps[sender][invalidatorSlot];
    if (invalidator & invalidatorBit != 0) revert InvalidNonce();

    return (invalidatorSlot, invalidator, invalidatorBit);
  }


  /* --------------- PRIVATE --------------- */

  /// @notice deduplication of taker order
  function _deduplicateOrder(address sender, uint256 nonce) private {
    (uint256 invalidatorSlot, uint256 invalidator, uint256 invalidatorBit) = verifyNonce(sender, nonce);
    _orderBitmaps[sender][invalidatorSlot] = invalidator | invalidatorBit;
  }

  /* --------------- INTERNAL --------------- */

  /// @notice transfer supported asset to beneficiary address
  function _transferToBeneficiary(address beneficiary, address asset, uint256 amount) internal {
    if (asset == NATIVE_TOKEN) {
      if (address(this).balance < amount) revert InvalidAmount();
      (bool success,) = (beneficiary).call{value: amount}("");
      if (!success) revert TransferFailed();
    } else {
      if (!_supportedAssets.contains(asset)) revert UnsupportedAsset();
      IERC20Upgradeable(asset).safeTransfer(beneficiary, amount);
    }
  }

  /// @notice transfer supported asset to redeemSilo address
  function _transferToRedeemSilo(address asset, uint256 amount) internal {
    if (asset == NATIVE_TOKEN) {
      if (address(this).balance < amount) revert InvalidAmount();
      (bool success,) = (address(redeemSilo)).call{value: amount}("");
      if (!success) revert TransferFailed();
    } else {
      if (!_supportedAssets.contains(asset)) revert UnsupportedAsset();
      IERC20Upgradeable(asset).safeTransfer(address(redeemSilo), amount);
    }
  }

  /// @notice transfer supported asset to array of custody addresses per defined ratio
  function _transferCollateral(
    uint256 amount,
    address asset,
    address benefactor,
    address[] calldata addresses,
    uint256[] calldata ratios
  ) internal {
    // cannot mint using unsupported asset or native ETH even if it is supported for redemptions
    if (!_supportedAssets.contains(asset) || asset == NATIVE_TOKEN) revert UnsupportedAsset();
    IERC20Upgradeable token = IERC20Upgradeable(asset);
    uint256 totalTransferred = 0;
    for (uint256 i = 0; i < addresses.length;) {
      uint256 amountToTransfer = (amount * ratios[i]) / ROUTE_REQUIRED_RATIO;
      token.safeTransferFrom(benefactor, addresses[i], amountToTransfer);
      totalTransferred += amountToTransfer;
      unchecked {
        ++i;
      }
    }
    uint256 remainingBalance = amount - totalTransferred;
    if (remainingBalance > 0) {
      token.safeTransferFrom(benefactor, addresses[addresses.length - 1], remainingBalance);
    }
  }

  /// @notice Sets the max mintPerBlock limit
  function _setMaxMintPerBlock(uint256 _maxMintPerBlock) internal {
    uint256 oldMaxMintPerBlock = maxMintPerBlock;
    maxMintPerBlock = _maxMintPerBlock;
    emit MaxMintPerBlockChanged(oldMaxMintPerBlock, maxMintPerBlock);
  }

  /// @notice Sets the max redeemPerBlock limit
  function _setMaxRedeemPerBlock(uint256 _maxRedeemPerBlock) internal {
    uint256 oldMaxRedeemPerBlock = maxRedeemPerBlock;
    maxRedeemPerBlock = _maxRedeemPerBlock;
    emit MaxRedeemPerBlockChanged(oldMaxRedeemPerBlock, maxRedeemPerBlock);
  }

  /// @notice Compute the current domain separator
  /// @return The domain separator for the token
  function _computeDomainSeparator() internal view returns (bytes32) {
    return keccak256(abi.encode(EIP712_DOMAIN, EIP_712_NAME, EIP712_REVISION, block.chainid, address(this)));
  }

  function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

  /**
    * @dev This empty reserved space is put in place to allow future versions to add new
    * variables without shifting down storage in the inheritance chain.
    * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
    */
  uint256[50] private __gap;
}
