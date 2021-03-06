pragma solidity 0.4.24;

import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "./interfaces/ChainlinkRequestInterface.sol";
import "./interfaces/OracleInterface.sol";
import "./interfaces/LinkTokenInterface.sol";

contract Oracle is ChainlinkRequestInterface, OracleInterface, Ownable {
  using SafeMath for uint256;

  uint256 constant public EXPIRY_TIME = 5 minutes;
  uint256 constant private MINIMUM_CONSUMER_GAS_LIMIT = 400000;
  // We initialize fields to 1 instead of 0 so that the first invocation
  // does not cost more gas.
  uint256 constant private ONE_FOR_CONSISTENT_GAS_COST = 1;
  uint256 constant private SELECTOR_LENGTH = 4;
  uint256 constant private EXPECTED_REQUEST_WORDS = 9;
  // solium-disable-next-line zeppelin/no-arithmetic-operations
  uint256 constant private MINIMUM_REQUEST_LENGTH = SELECTOR_LENGTH + (32 * EXPECTED_REQUEST_WORDS);

  LinkTokenInterface internal LinkToken;
  mapping(bytes32 => bytes32) private commitments;
  mapping(address => bool) private authorizedNodes;
  uint256 private withdrawableTokens = ONE_FOR_CONSISTENT_GAS_COST;

  event RunRequest(
    bytes32 indexed specId,
    address indexed requester,
    uint256 indexed payment,
    uint256 requestId,
    uint256 dataVersion,
    address callbackAddr,
    bytes4 callbackFunctionId,
    uint256 cancelExpiration,
    bytes data
  );

  event CancelRequest(
    bytes32 indexed requestId
  );

  constructor(address _link) Ownable() public {
    LinkToken = LinkTokenInterface(_link);
  }

  function onTokenTransfer(
    address _sender,
    uint256 _amount,
    bytes _data
  )
    public
    onlyLINK
    validRequestLength(_data)
    permittedFunctionsForLINK(_data)
  {
    assembly {
      // solium-disable-next-line security/no-low-level-calls
      mstore(add(_data, 36), _sender) // ensure correct sender is passed
      // solium-disable-next-line security/no-low-level-calls
      mstore(add(_data, 68), _amount)    // ensure correct amount is passed
    }
    // solium-disable-next-line security/no-low-level-calls
    require(address(this).delegatecall(_data), "Unable to create request"); // calls requestData
  }

  function requestData(
    address _sender,
    uint256 _payment,
    uint256 _dataVersion,
    bytes32 _specId,
    address _callbackAddress,
    bytes4 _callbackFunctionId,
    uint256 _nonce,
    bytes _data
  )
    external
    onlyLINK
    checkCallbackAddress(_callbackAddress)
  {
    bytes32 requestId = keccak256(abi.encodePacked(_sender, _nonce));
    require(commitments[requestId] == 0, "Must use a unique ID");
    uint256 expiration = now.add(EXPIRY_TIME);

    commitments[requestId] = keccak256(
      abi.encodePacked(
        _payment,
        _callbackAddress,
        _callbackFunctionId,
        expiration
      )
    );

    emit RunRequest(
      _specId,
      _sender,
      _payment,
      uint256(requestId),
      _dataVersion,
      _callbackAddress,
      _callbackFunctionId,
      expiration,
      _data);
  }

  function fulfillData(
    uint256 _requestId,
    uint256 _payment,
    address _callbackAddress,
    bytes4 _callbackFunctionId,
    uint256 _expiration,
    bytes32 _data
  )
    external
    onlyAuthorizedNode
    isValidRequest(_requestId)
    returns (bool)
  {
    bytes32 requestId = bytes32(_requestId);
    bytes32 paramsHash = keccak256(
      abi.encodePacked(
        _payment,
        _callbackAddress,
        _callbackFunctionId,
        _expiration
      )
    );
    require(commitments[requestId] == paramsHash, "Params do not match request ID");
    withdrawableTokens = withdrawableTokens.add(_payment);
    delete commitments[requestId];
    require(gasleft() >= MINIMUM_CONSUMER_GAS_LIMIT, "Must provide consumer enough gas");
    // All updates to the oracle's fulfillment should come before calling the
    // callback(addr+functionId) as it is untrusted.
    // See: https://solidity.readthedocs.io/en/develop/security-considerations.html#use-the-checks-effects-interactions-pattern
    return _callbackAddress.call(_callbackFunctionId, requestId, _data); // solium-disable-line security/no-low-level-calls
  }

  function getAuthorizationStatus(address _node) external view returns (bool) {
    return authorizedNodes[_node];
  }

  function setFulfillmentPermission(address _node, bool _allowed) external onlyOwner {
    authorizedNodes[_node] = _allowed;
  }

  function withdraw(address _recipient, uint256 _amount)
    external
    onlyOwner
    hasAvailableFunds(_amount)
  {
    withdrawableTokens = withdrawableTokens.sub(_amount);
    assert(LinkToken.transfer(_recipient, _amount));
  }

  function withdrawable() external view onlyOwner returns (uint256) {
    return withdrawableTokens.sub(ONE_FOR_CONSISTENT_GAS_COST);
  }

  function cancel(
    bytes32 _requestId,
    uint256 _payment,
    bytes4 _callbackFunc,
    uint256 _expiration
  ) external {
    bytes32 paramsHash = keccak256(
      abi.encodePacked(
        _payment,
        msg.sender,
        _callbackFunc,
        _expiration)
    );
    require(paramsHash == commitments[_requestId], "Params do not match request ID");
    require(_expiration <= now, "Request is not expired");

    delete commitments[_requestId];
    emit CancelRequest(_requestId);

    assert(LinkToken.transfer(msg.sender, _payment));
  }

  // MODIFIERS

  modifier hasAvailableFunds(uint256 _amount) {
    require(withdrawableTokens >= _amount.add(ONE_FOR_CONSISTENT_GAS_COST), "Amount requested is greater than withdrawable balance");
    _;
  }

  modifier isValidRequest(uint256 _requestId) {
    require(commitments[bytes32(_requestId)] != 0, "Must have a valid requestId");
    _;
  }

  modifier onlyAuthorizedNode() {
    require(authorizedNodes[msg.sender] || msg.sender == owner, "Not an authorized node to fulfill requests");
    _;
  }

  modifier onlyLINK() {
    require(msg.sender == address(LinkToken), "Must use LINK token");
    _;
  }

  modifier permittedFunctionsForLINK(bytes _data) {
    bytes4 funcSelector;
    assembly {
      // solium-disable-next-line security/no-low-level-calls
      funcSelector := mload(add(_data, 32))
    }
    require(funcSelector == this.requestData.selector, "Must use whitelisted functions");
    _;
  }

  modifier checkCallbackAddress(address _to) {
    require(_to != address(LinkToken), "Cannot callback to LINK");
    _;
  }

  modifier validRequestLength(bytes _data) {
    require(_data.length >= MINIMUM_REQUEST_LENGTH, "Invalid request length");
    _;
  }

}
